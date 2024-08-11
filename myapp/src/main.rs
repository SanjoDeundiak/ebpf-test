use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf_ingress = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/myapp_ingress"
    ))?;
    #[cfg(debug_assertions)]
    let mut bpf_egress = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/myapp_egress"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf_ingress = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/myapp_ingress"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_egress = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/myapp_egress"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf_ingress) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger for ingress: {}", e);
    }

    if let Err(e) = BpfLogger::init(&mut bpf_egress) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger for egress: {}", e);
    }

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);

    let program_ingress: &mut SchedClassifier =
        bpf_ingress.program_mut("ingress").unwrap().try_into()?;
    program_ingress.load()?;
    program_ingress.attach(&opt.iface, TcAttachType::Ingress)?;

    let program_egress: &mut SchedClassifier =
        bpf_egress.program_mut("egress").unwrap().try_into()?;
    program_egress.load()?;
    program_egress.attach(&opt.iface, TcAttachType::Egress)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
