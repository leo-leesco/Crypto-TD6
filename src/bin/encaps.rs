use std::env::args;

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
    let mut pk: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
    hex::decode_to_slice(
        args().nth(1).expect("Please provide the public key"),
        &mut pk,
    )
    .expect("Could not parse public key as a 32-byte hex string");

    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();

    let mut rng = thread_rng();
    let mut m = [0u8; PUBLIC_KEY_LENGTH];
    rng.fill(&mut m);

    let mut g1 = Shake128::default();
    g1.update(pk.as_bytes());
    let mut pk_hash = [0u8; 128];
    g1.finalize_xof().read(&mut pk_hash);

    let mut g2 = Shake128::default();
    g2.update(&pk_hash);
    g2.update(&m);
    let mut rk = [0u8; 128];
    g2.finalize_xof().read(&mut rk);

    let r = &rk[..rk.len() / 2];
    let k = &rk[rk.len() / 2..];

    let c: Vec<u8> = m
        .iter()
        .zip(pk.as_bytes())
        .zip(r)
        .map(|((a, b), c)| a ^ b ^ c)
        .collect();

    let mut f = Shake128::default();
    f.update(&c);
    f.update(k);
    let mut k = [0u8; 16];
    f.finalize_xof().read(&mut k);

    println!("{}", hex::encode(c));
    println!("{}", hex::encode(k));
}
