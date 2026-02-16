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

use std::{
    ffi::CStr,
    net::{AddrParseError, IpAddr, SocketAddr},
    os::unix::fs::MetadataExt,
    path::PathBuf,
};

use async_from::{AsyncTryFrom, AsyncTryInto};
use aya::{
    maps::{MapData, RingBuf},
    programs::{CgroupAttachMode, CgroupSockAddr},
};
use bytemuck::PodCastError;
use eyre::{Result, eyre};
use futures::{FutureExt, Stream, StreamExt, TryStreamExt};
use ipnetwork::{IpNetwork, IpNetworkError};
use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use kube::{Api, Client, api::ListParams};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{Resource, logs::SdkLoggerProvider};
use ouroboros::self_referencing;
use tokio_stream::wrappers::ReadDirStream;
use tracing::{instrument, level_filters::LevelFilter};
#[rustfmt::skip]
use tracing::{debug, info, warn};
use procfs::process::Process;
use tokio::{
    fs::DirEntry,
    io::{Interest, unix::AsyncFd},
};
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    EnvFilter, Layer,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

#[instrument]
#[tokio::main]
async fn main() -> eyre::Result<()> {
    let log_provider = match opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .build()
    {
        Ok(log_exporter) => SdkLoggerProvider::builder()
            .with_resource(Resource::builder().with_service_name("roy").build())
            .with_batch_exporter(log_exporter)
            .build(),
        Err(e) => {
            eprintln!("Cannot initialize OTLP log exporter: {e:?}");
            SdkLoggerProvider::builder()
                .with_batch_exporter(opentelemetry_stdout::LogExporter::default())
                .build()
        }
    };
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_span_events(FmtSpan::NONE)
                .with_filter(EnvFilter::from_default_env()),
        )
        .with(ErrorLayer::default())
        .with(OpenTelemetryTracingBridge::new(&log_provider).with_filter(LevelFilter::INFO))
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
        info!(target: "roy-log", message = format!(
            "remove limit on locked memory failed, ret is: {ret}. This is fine for new kernel that use the memcg based accounting."
        ));
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
            warn!(target: "roy-log", message = format!("failed to initialize eBPF logger: {e:?}"));
        }
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let roy4: &mut CgroupSockAddr = ebpf.program_mut("roy4").unwrap().try_into()?;
    roy4.load()?;
    let cgroup = guess_kubepods_cgroup()
        .await?
        .ok_or_else(|| eyre!("Could not find K8S Cgroup"))?;
    let cgroup = std::fs::File::open(cgroup)?;
    roy4.attach(cgroup, CgroupAttachMode::Single)?;

    let roy6: &mut CgroupSockAddr = ebpf.program_mut("roy6").unwrap().try_into()?;
    roy6.load()?;
    let cgroup = guess_kubepods_cgroup()
        .await?
        .ok_or_else(|| eyre!("Could not find K8S Cgroup"))?;
    let cgroup = std::fs::File::open(cgroup)?;
    roy6.attach(cgroup, CgroupAttachMode::Single)?;

    let ring = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut ring = AsyncFd::with_interest(ring, Interest::READABLE)?;
    loop {
        if let Err(e) = handle_ebpf_output(&mut ring).await {
            warn!(target: "roy-log", message = format!("handle_ebpf_output failed: {e:?}"));
        }
    }
}

async fn handle_ebpf_output(ring: &mut AsyncFd<RingBuf<&mut MapData>>) -> Result<()> {
    let mut guard = ring.readable_mut().await?;
    match guard.try_io(|inner| {
        inner
            .get_mut()
            .next()
            .map(|x| {
                let message: Result<&roy_common::Event, PodCastError> =
                    bytemuck::try_from_bytes(x.as_ref());
                message.copied()
            })
            .transpose()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}")))
    }) {
        Ok(Ok(Some(x))) => {
            tokio::task::spawn(async move {
                let lan = [
                    "192.168.0.0/16",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    // "127.0.0.0/8",
                    "169.254.0.0/16",
                    // "224.0.0.0/4",
                    "240.0.0.0/4",
                    "fc00::/7",
                ]
                .into_iter()
                .map(str::parse)
                .collect::<Result<Vec<IpNetwork>, IpNetworkError>>()?;
                let special_addr = std::iter::once("::ffff:127.0.0.1")
                    .map(str::parse)
                    .collect::<Result<Vec<IpAddr>, AddrParseError>>()?;
                let ip = if x.ipv == 0 {
                    (x.addr4.to_le_bytes() as [u8; 4]).into()
                } else {
                    annoying(x.addr6).into()
                };
                if lan.iter().all(|subnet| !subnet.contains(ip))
                    && !special_addr.contains(&ip)
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    && !ip.is_unspecified()
                {
                    let event: Event = x.async_try_into().await?;
                    report(event);
                }
                Ok(()) as eyre::Result<()>
            })
            .await??;
        }
        Ok(Ok(None)) => (),
        Ok(Err(e)) => Err(e)?,
        Err(e) => Err(eyre!("{e:?}"))?,
    }

    Ok(())
}

fn report(event: Event) {
    let skip_annotation = "roy.magiclouds.cn/skip".to_string();
    let empty_string = String::new();
    if let Some(pod) = event.pod {
        let p = pod.borrow_pod();
        let c = pod.borrow_container();
        let ns = p.metadata.namespace.as_ref().unwrap_or(&empty_string);
        let n = p.metadata.name.as_ref().unwrap_or(&empty_string);
        let cn = c.map(|c| &c.name).unwrap_or(&empty_string);
        if pod
            .borrow_pod()
            .metadata
            .annotations
            .as_ref()
            .is_none_or(|a| a.get(&skip_annotation).is_none_or(|v| v != "true"))
        {
            match event.process {
                PidOrCmd::Pid(pid) => info!(target: "roy-report",
                    pid = pid.to_string(),
                    socket_add = event.socket_addr.to_string(),
                    namespace = ns,
                    pod = n,
                    container = cn,
                ),
                PidOrCmd::Cmdline(items) => info!(target: "roy-report",
                    cli = items.join(" "),
                    socket_add = event.socket_addr.to_string(),
                    namespace = ns,
                    pod = n,
                    container = cn,
                ),
                PidOrCmd::PartialCmd(cmd) => info!(target: "roy-report",
                    cmd = cmd,
                    socket_add = event.socket_addr.to_string(),
                    namespace = ns,
                    pod = n,
                    container = cn,
                ),
            }
        } else {
            debug!("Skip logging {ns}/{n}/{cn}");
        }
    } else {
        match event.process {
            PidOrCmd::Pid(pid) => info!(target: "roy-report",
                pid = pid.to_string(),
                socket_add = event.socket_addr.to_string(),
            ),
            PidOrCmd::Cmdline(items) => info!(target: "roy-report",
                cli = items.join(" "),
                socket_add = event.socket_addr.to_string(),
            ),
            PidOrCmd::PartialCmd(cmd) => info!(target: "roy-report",
                cmd = cmd,
                socket_add = event.socket_addr.to_string(),
            ),
        }
    }
}

// IPv6 is always BE
// SockAddr is probably host byte order, which is LE on x86
// Hence it requires double converting
#[allow(clippy::cast_possible_truncation)]
const fn annoying(input: [u32; 4]) -> [u16; 8] {
    let be = [
        input[0].to_be(),
        input[1].to_be(),
        input[2].to_be(),
        input[3].to_be(),
    ];

    [
        (be[0] >> 16) as u16,
        be[0] as u16,
        (be[1] >> 16) as u16,
        be[1] as u16,
        (be[2] >> 16) as u16,
        be[2] as u16,
        (be[3] >> 16) as u16,
        be[3] as u16,
    ]
}

#[derive(Debug)]
struct Event {
    process: PidOrCmd,
    socket_addr: SocketAddr,
    pod: Option<K8SPod>,
}
#[async_from::async_trait]
impl AsyncTryFrom<roy_common::Event> for Event {
    type Error = eyre::Report;

    async fn async_try_from(value: roy_common::Event) -> Result<Self, Self::Error> {
        let (pc, cmd): (Option<(String, String)>, PidOrCmd) = match get_info_from_process(&value) {
            Ok(x) => x,
            Err(e) => {
                info!(target: "roy-log", message = format!("Unable to fetch process data for Pid {}: {e:?}", value.pid));
                match get_info_from_cgroup(&value).await {
                    Ok(x) => x,
                    Err(e) => {
                        info!(target: "roy-log", message = format!("Unable to fetch cgroup data for Pid {}: {e:?}", value.pid));
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
            if let Some((ns, n)) = pod.and_then(|p| {
                p.metadata
                    .namespace
                    .and_then(|ns| p.metadata.name.map(|n| (ns, n)))
            }) {
                let pods: Api<Pod> = Api::namespaced(client, &ns);
                let pod = pods.get_opt(&n).await?;
                if let Some(pod) = pod {
                    ret = Some(
                        K8SPodBuilder {
                            pod,
                            container_builder: |pod| {
                                let x = pod
                                    .status
                                    .as_ref()?
                                    .container_statuses
                                    .as_ref()?
                                    .iter()
                                    .find(|cs| {
                                        cs.container_id
                                            .as_ref()
                                            .is_some_and(|x| x.contains(&container_uid))
                                    })?;
                                Some(x)
                            },
                        }
                        .build(),
                    );
                }
            }
        }
        Ok(Self {
            process: cmd,
            socket_addr: (
                if value.ipv == 0 {
                    IpAddr::from(value.addr4.to_le_bytes() as [u8; 4])
                } else {
                    annoying(value.addr6).into()
                },
                u16::try_from(value.port)?.to_be(),
            )
                .into(),
            pod: ret,
        })
    }
}

fn get_info_from_process(
    value: &roy_common::Event,
) -> Result<(Option<(String, String)>, PidOrCmd)> {
    let proc = Process::new_with_root(PathBuf::from("/host/proc").join(value.pid.to_string()))?;
    debug!("get proc");
    let (pod_uid, container_uid) = proc
        .cgroups()?
        .into_iter()
        .find_map(|x| {
            // The path is relevent. And due to the mount of host proc
            // it would start at current container (the one runnign Roy).
            // Then ../../ to kubepods level.
            let mut segs = x.pathname.split('/');
            if segs.next()?.is_empty() && segs.next()? == ".." && segs.next()? == ".." {
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

async fn get_info_from_cgroup(
    value: &roy_common::Event,
) -> Result<(Option<(String, String)>, PidOrCmd)> {
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

    let cmd = PidOrCmd::PartialCmd(CStr::from_bytes_until_nul(&value.cmd)?.to_str()?.to_owned());

    Ok((
        pod.and_then(|p| {
            container
                .and_then(|x| x.file_name().to_str().map(std::borrow::ToOwned::to_owned))
                .map(|c| (p, c))
        }),
        cmd,
    )) as Result<_>
}

// #[allow(clippy::ref_option_ref)] does not work
#[self_referencing]
#[derive(Debug)]
struct K8SPod {
    pod: Pod,
    #[borrows(pod)]
    #[covariant]
    container: Option<&'this ContainerStatus>,
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
    info!(target: "roy-log", message = format!("{ret:?}"));
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
