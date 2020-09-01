use libtor::{Tor, TorFlag, TorAddress, HiddenServiceVersion};

fn main() {
    Tor::new()
    .flag(TorFlag::DataDirectory("/tmp/tor-rust".into()))
    .flag(TorFlag::SocksPort(19050))
    .flag(TorFlag::HiddenServiceDir("/tmp/tor-rust/hs-dir".into()))
    .flag(TorFlag::HiddenServiceVersion(HiddenServiceVersion::V3))
    .flag(TorFlag::HiddenServicePort(TorAddress::Port(8000), None.into()))
    .start().expect("Tor failed to start");
}
