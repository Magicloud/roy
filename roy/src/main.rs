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

use std::{fs, net::SocketAddr, os::unix::fs::MetadataExt};

use async_from::{AsyncTryFrom, AsyncTryInto};
use async_walkdir::{Filtering, WalkDir};
use aya::{
    maps::RingBuf,
    programs::{CgroupAttachMode, CgroupSockAddr},
};
use eyre::eyre;
use futures::StreamExt;
use ipnetwork::{IpNetwork, IpNetworkError};
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client, api::ListParams};
use tracing::instrument;
#[rustfmt::skip]
use tracing::{debug, info, warn};
use procfs::process::Process;
use roy_common::EventV4;
use tokio::io::{Interest, unix::AsyncFd};
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
        debug!("remove limit on locked memory failed, ret is: {ret}");
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
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut CgroupSockAddr = ebpf.program_mut("roy4").unwrap().try_into()?;
    program.load()?;
    // K3S cgroup
    let cgroup = fs::File::open("/sys/fs/cgroup/kubepods")?;
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
            if lan.iter().all(|subnet| !subnet.contains(ip))
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unspecified()
            {
                let event: Event = x.async_try_into().await?;
                info!("{event:?}");
            }
        }
    }
}

#[derive(Debug)]
struct Event {
    process: PidOrCmd,
    socket_addr: SocketAddr,
    pod: K8SID,
}
#[async_from::async_trait]
impl AsyncTryFrom<EventV4> for Event {
    type Error = eyre::Error;

    async fn async_try_from(value: EventV4) -> Result<Self, Self::Error> {
        let (pod_uid, cmd) = if let Ok(proc) = Process::new(value.pid.try_into()?) {
            let pod_uid = proc
                .cgroups()?
                .into_iter()
                .find_map(|x| {
                    let segs = x.pathname.split('/');
                    // first path seg should be "kubepods"
                    segs.skip_while(|x| *x != "kubepods")
                        .find(|x| x.starts_with("pod"))
                        .and_then(|x| x.strip_prefix("pod").map(std::string::ToString::to_string))
                })
                .ok_or_else(|| eyre!("Could not find Pod UID for PID {}", value.pid))?;
            let cmd = proc
                .cmdline()
                .map_or(PidOrCmd::Pid(value.pid), PidOrCmd::Cmdline);

            (pod_uid, cmd)
        } else {
            // The process is exited.
            let mut pod_uid = None;
            while let Some(x) = WalkDir::new("/sys/fs/cgroup/kubepods")
                .filter(|x| async move {
                    if x.file_type().await.is_ok_and(|x| x.is_dir()) {
                        Filtering::Continue
                    } else {
                        Filtering::Ignore
                    }
                })
                .next()
                .await
            {
                let cgroup_folder = x?;
                if cgroup_folder
                    .metadata()
                    .await
                    .is_ok_and(|x| x.ino() == value.cgroup)
                {
                    pod_uid = cgroup_folder
                        .path()
                        .to_str()
                        .and_then(|x| x.strip_prefix("pod").map(std::string::ToString::to_string));
                    break;
                }
            }
            let cmd = PidOrCmd::PartialCmd(String::from_utf8_lossy(&value.cmd).into());

            (pod_uid.unwrap_or_default(), cmd)
        };
        let pods: Api<Pod> = Api::all(Client::try_default().await?);
        let pod = pods
            .list_metadata(&ListParams::default())
            .await?
            .into_iter()
            .find(|x| x.metadata.uid.as_ref().is_some_and(|x| *x == pod_uid))
            .map(|x| K8SID {
                namespace: x.metadata.namespace,
                name: x.metadata.name.unwrap_or_default(),
            })
            .ok_or_else(|| eyre!("Could not find the Pod for PID {}", value.pid))?;
        Ok(Self {
            process: cmd,
            socket_addr: (
                value.addr.to_le_bytes() as [u8; 4],
                u16::try_from(value.port)?.to_be(),
            )
                .into(),
            pod,
        })
    }
}

#[derive(Debug)]
struct K8SID {
    namespace: Option<String>,
    name: String,
}

#[derive(Debug)]
enum PidOrCmd {
    Pid(u32),
    Cmdline(Vec<String>),
    PartialCmd(String),
}
