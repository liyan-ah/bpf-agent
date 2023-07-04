use aya::maps::AsyncPerfEventArray;
use aya::programs::UProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bpf_agent_common::Name;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
    #[clap(short, long)]
    sym: Option<String>,
    #[clap(short, long)]
    exe: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Allow current process to lock memory for eBPF resources.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/bpf-agent"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/bpf-agent"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut UProbe =
        bpf.program_mut("bpf_agent").unwrap().try_into()?;
    program.load()?;
    program.attach(opt.sym.as_deref(), 0, opt.exe, opt.pid)?;

    let mut perf_array =
        AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let name: Name =
                        unsafe { std::ptr::read(buf.as_ptr() as *const _) };
                    let n_buf = &name.name[0..name.name_length as usize];
                    println!("name v is: {:?}", String::from_utf8(n_buf.to_vec()));
                    println!("{:?}", n_buf);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
