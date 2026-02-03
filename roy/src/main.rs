#![warn(clippy::cargo)]
#![warn(clippy::complexity)]
#![warn(clippy::correctness)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::perf)]
#![warn(clippy::style)]
#![warn(clippy::suspicious)]
#![allow(clippy::future_not_send)]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::wildcard_dependencies)]

use std::{net::SocketAddr, os::unix::fs::MetadataExt, path::PathBuf};

use async_from::{AsyncTryFrom, AsyncTryInto};
use aya::{
    maps::RingBuf,
    programs::{CgroupAttachMode, CgroupSockAddr},
};
use eyre::{Result, eyre};
use futures::{FutureExt, Stream, StreamExt, TryStreamExt};
use ipnetwork::{IpNetwork, IpNetworkError};
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client, api::ListParams};
use tokio_stream::wrappers::ReadDirStream;
use tracing::instrument;
#[rustfmt::skip]
use tracing::{debug, info, warn};
use procfs::process::Process;
use roy_common::EventV4;
use tokio::{
    fs::DirEntry,
    io::{Interest, unix::AsyncFd},
};
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

#[instrument]
#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NONE))
        .with(tracing_error::ErrorLayer::default())
        .try_init()?;
    color_eyre::install()?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const rlim) };
    if ret != 0 {
        info!(
            "remove limit on locked memory failed, ret is: {ret}. This is fine for new kernel that use the memcg based accounting."
        );
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/roy"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    // guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut CgroupSockAddr = ebpf.program_mut("roy4").unwrap().try_into()?;
    program.load()?;
    let cgroup = guess_kubepods_cgroup()
        .await?
        .ok_or_else(|| eyre!("Could not find K8S Cgroup"))?;
    let cgroup = std::fs::File::open(cgroup)?;
    program.attach(cgroup, CgroupAttachMode::Single)?;

    let ring = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut ring = AsyncFd::with_interest(ring, Interest::READABLE)?;
    loop {
        let mut guard = ring.readable_mut().await?;
        if let Ok(x) = guard.try_io(|inner| {
            inner
                .get_mut()
                .next()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::WouldBlock, "no data"))
                .map(|x| {
                    let message: &EventV4 = bytemuck::from_bytes(x.as_ref());
                    *message
                })
        }) {
            tokio::task::spawn(async {
                let x = x?;
                let lan = [
                    "192.168.0.0/16",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    // "127.0.0.0/8",
                    "169.254.0.0/16",
                    // "224.0.0.0/4",
                    "240.0.0.0/4",
                ]
                .into_iter()
                .map(str::parse)
                .collect::<Result<Vec<IpNetwork>, IpNetworkError>>()?;
                let ip = (x.addr.to_le_bytes() as [u8; 4]).into();
                debug!("{ip:?}");
                if lan.iter().all(|subnet| !subnet.contains(ip))
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    && !ip.is_unspecified()
                {
                    let event: Event = x.async_try_into().await?;
                    info!("{event:?}");
                }
                Ok(()) as eyre::Result<()>
            })
            .await??;
        }
    }
}

#[derive(Debug)]
struct Event {
    process: PidOrCmd,
    socket_addr: SocketAddr,
    pod: Option<K8SPod>,
}
#[async_from::async_trait]
impl AsyncTryFrom<EventV4> for Event {
    type Error = eyre::Report;

    async fn async_try_from(value: EventV4) -> Result<Self, Self::Error> {
        let (pc, cmd): (Option<(String, String)>, PidOrCmd) = match get_info_from_process(&value) {
            Ok(x) => x,
            Err(e) => {
                info!("{e:?}");
                match get_info_from_cgroup(&value).await {
                    Ok(x) => x,
                    Err(e) => {
                        info!("{e:?}");
                        (
                            None,
                            PidOrCmd::PartialCmd(String::from_utf8_lossy(&value.cmd).into()),
                        )
                    }
                }
            }
        };
        let mut ret = None;
        if let Some((pod_uid, container_uid)) = pc {
            debug!("Pod: {pod_uid}");
            debug!("Container: {container_uid}");
            let client = Client::try_default().await?;
            let pods: Api<Pod> = Api::all(client.clone());
            let pod = pods
                .list_metadata(&ListParams::default())
                .await?
                .into_iter()
                .find(|x| x.metadata.uid.as_ref().is_some_and(|x| pod_uid.contains(x)));
            if pod.is_some() {
                debug!("Found pod");
            } else {
                debug!("Found no pod");
            }
            if let Some((ns, n)) = pod.and_then(|p| {
                p.metadata
                    .namespace
                    .and_then(|ns| p.metadata.name.map(|n| (ns, n)))
            }) {
                let pods: Api<Pod> = Api::namespaced(client, &ns);
                let pod = pods.get_opt(&n).await?;
                let container = pod.and_then(|p| {
                    // Is it possible that I cannot find the container?
                    Some(
                        p.status?
                            .container_statuses?
                            .iter()
                            .find(|cs| {
                                cs.container_id
                                    .as_ref()
                                    .is_some_and(|x| x.contains(&container_uid))
                            })?
                            .name
                            .clone(),
                    )
                });
                if container.is_some() {
                    debug!("Found container");
                } else {
                    debug!("Found no container");
                }
                ret = container.map(|c| K8SPod {
                    namespace: ns,
                    name: n,
                    container_name: c,
                });
            }
        }
        Ok(Self {
            process: cmd,
            socket_addr: (
                value.addr.to_le_bytes() as [u8; 4],
                u16::try_from(value.port)?.to_be(),
            )
                .into(),
            pod: ret,
        })
    }
}

fn get_info_from_process(value: &EventV4) -> Result<(Option<(String, String)>, PidOrCmd)> {
    let proc = Process::new_with_root(PathBuf::from("/host/proc").join(value.pid.to_string()))?;
    debug!("get proc");
    let (pod_uid, container_uid) = proc
        .cgroups()?
        .into_iter()
        .find_map(|x| {
            let mut segs = x.pathname.split('/');
            if segs.next()?.contains("kubepods") {
                let _pod_type = segs.next()?;
                let pod = segs.next()?;
                let container = segs.next()?;
                Some((pod.to_owned(), container.to_owned()))
            } else {
                None
            }
        })
        .ok_or_else(|| {
            eyre!(
                "Could not extract pod/container data from cgroup for PID {}",
                value.pid
            )
        })?;
    let cmd = proc
        .cmdline()
        .map_or(PidOrCmd::Pid(value.pid), PidOrCmd::Cmdline);

    Ok((Some((pod_uid, container_uid)), cmd)) as eyre::Result<_>
}

async fn get_info_from_cgroup(value: &EventV4) -> Result<(Option<(String, String)>, PidOrCmd)> {
    let containers = walk_containers()
        .await?
        .ok_or_else(|| eyre!("Kubepods CGROUP not found"))?;
    let container = containers
        .try_filter_map(|container| {
            async {
                if container.metadata().await?.ino() == value.cgroup {
                    Ok(Some(container))
                } else {
                    Ok(None)
                }
            }
            .boxed()
        })
        .next()
        .await
        .transpose()?;
    let pod = container.as_ref().and_then(|x| {
        x.path()
            .parent()
            .and_then(|x| x.file_name())
            .and_then(|x| x.to_str())
            .map(std::borrow::ToOwned::to_owned)
    });

    let cmd = PidOrCmd::PartialCmd(String::from_utf8_lossy(&value.cmd).into());

    Ok((
        pod.and_then(|p| {
            container
                .and_then(|x| x.file_name().to_str().map(std::borrow::ToOwned::to_owned))
                .map(|c| (p, c))
        }),
        cmd,
    )) as Result<_>
}

#[derive(Debug)]
struct K8SPod {
    namespace: String,
    name: String,
    container_name: String,
}

#[derive(Debug)]
enum PidOrCmd {
    Pid(u32),
    Cmdline(Vec<String>),
    PartialCmd(String),
}

async fn guess_kubepods_cgroup() -> Result<Option<PathBuf>> {
    let mut root = tokio::fs::read_dir("/sys/fs/cgroup").await?;
    let mut ret = None;
    while let Some(subdir) = root.next_entry().await? {
        if subdir
            .file_name()
            .into_string()
            .map_err(|x| eyre!("Unable to handle {x:?}"))?
            .contains("kubepods")
        {
            ret = Some(subdir.path());
            break;
        }
    }
    info!("{ret:?}");
    Ok(ret)
}

async fn walk_containers() -> Result<Option<impl Stream<Item = Result<DirEntry, std::io::Error>>>> {
    if let Some(kubepods) = guess_kubepods_cgroup().await? {
        let pods = ReadDirStream::new(tokio::fs::read_dir(kubepods).await?)
            .try_filter_map(|x| {
                async move {
                    match x.file_type().await {
                        Ok(y) => {
                            if y.is_dir() {
                                Ok(Some(
                                    ReadDirStream::new(tokio::fs::read_dir(x.path()).await?)
                                        .try_filter_map(|z| {
                                            async {
                                                z.file_type().await.map(|w| {
                                                    if w.is_dir() { Some(z) } else { None }
                                                })
                                            }
                                            .boxed()
                                        }),
                                ))
                            } else {
                                Ok(None)
                            }
                        }
                        Err(e) => Err(e),
                    }
                }
                .boxed()
            })
            .try_flatten();
        let containers = pods
            .and_then(|pod| {
                async move {
                    let ret = ReadDirStream::new(tokio::fs::read_dir(pod.path()).await?)
                        .try_filter_map(|x| {
                            async move {
                                x.file_type()
                                    .await
                                    .map(|y| if y.is_dir() { Some(x) } else { None })
                            }
                            .boxed()
                        });
                    Ok(ret)
                }
                .boxed()
            })
            .try_flatten();
        Ok(Some(containers))
    } else {
        Ok(None)
    }
}
