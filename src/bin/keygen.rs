use std::env::args;
use std::fs::OpenOptions;
use std::fs::write;
use std::io::Write;

use ed25519_dalek::PUBLIC_KEY_LENGTH;
use ed25519_dalek::SigningKey;
use rand::Rng;
use rand::rngs::OsRng;
use rand::thread_rng;
use sha3::Shake128;
use sha3::digest::ExtendableOutput;
use sha3::digest::Update;
use sha3::digest::XofReader;

fn main() {
    let prefix = args()
        .nth(1)
        .expect("Please provide a filename to write to <filename>.sk and <filename>.pk");

    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();

    let mut rng = thread_rng();
    let mut s = [0u8; PUBLIC_KEY_LENGTH];
    rng.fill(&mut s);

    let mut g1 = Shake128::default();
    g1.update(pk.as_bytes());
    let mut pk_hash = [0u8; 128];
    g1.finalize_xof().read(&mut pk_hash);

    let hex_pk = hex::encode(pk.to_bytes());
    println!("{hex_pk}");

    write(format!("{prefix}.sk"), "")
        .unwrap_or_else(|_| panic!("Could not clear {prefix}.sk before writing to it"));
    let mut sk_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(format!("{prefix}.sk"))
        .unwrap_or_else(|_| panic!("Could not open {prefix}.sk in append mode"));

    writeln!(sk_file, "{}", hex::encode(sk.to_bytes()))
        .unwrap_or_else(|_| panic!("Could not write secret key to {prefix}.sk"));
    writeln!(sk_file, "{}", hex::encode(s))
        .unwrap_or_else(|_| panic!("Could not write random byte string to {prefix}.sk"));
    writeln!(sk_file, "{}", hex_pk)
        .unwrap_or_else(|_| panic!("Could not write public key to {prefix}.sk"));
    writeln!(sk_file, "{}", hex::encode(pk_hash))
        .unwrap_or_else(|_| panic!("Could not write public key hash to {prefix}.sk"));
}
