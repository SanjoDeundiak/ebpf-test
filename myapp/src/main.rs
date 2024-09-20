use aya::programs::SchedClassifier;
use aya::Bpf;
use std::env;

fn main() {
    // env_logger::init();

    let args: Vec<String> = env::args().collect();

    let filename = &args[1];

    let ebpf = std::fs::read(filename).unwrap();

    let mut bpf = Bpf::load(&ebpf).unwrap();

    let program_ingress: &mut SchedClassifier = bpf
        .program_mut("ockam_ingress")
        .unwrap()
        .try_into()
        .unwrap();

    program_ingress.load().unwrap();
}
