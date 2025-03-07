# ElGamal-style KEM

Please check the latest version on [GitHub](https://github.com/leo-leesco/Crypto-TD6).

## Build

`cargo build` produces `keygen`, `encaps` and `decaps` in `target/debug`.

If you want the optimized version, run `cargo build --release`, and the executables can then be found in `target/release`.

## Requirements

`keygen` expects a filename, named `prefix`, and writes the (32-byte hex encoded) public key to `stdout` and the secret key to `prefix.sk`.

`encaps` expects a (32-byte hex encoded) public key and writes a ($N=(32+$ length of encrypted message) hex encoded) ciphertext and a (16-byte hex encoded) symmetric encryption key to `stdout` on two separate lines.

`decaps` expects the filename of the private key and the $N$-byte (hex encoded) ciphertext and writes a (16-byte hex encoded) symmetric encryption key to `stdout`.

## Theoretical framework

### `keygen`

We first define `PKE.keygen` based on [`curve25519`](https://github.com/leo-leesco/Crypto-TD5) and `G1` is a hash function (here `shake128`).

```pseudo
(PK,SK)=PKE.keygen()
s=random_byte_string()
PKH=G1(PK)
SK'=(SK,s,PK,PKH)
return (PK,SK')
```
### `encaps`

`PKE.encrypt` is a simple XOR and `G2` and `F` are hash functions (here `shake128`).

```pseudo
M=random()
(r || k)=G2(G1(PK) || M) // (r || k) means splitting the string, otherwise it means concatenation of strings
C=PKE.encrypt(M,PK,r)
K=F(C || k)
return (C,K)
```

### `decaps`

Finally, `PKE.decrypt` is based on [`curve25519`](https://github.com/leo-leesco/Crypto-TD5).

```pseudo
M=PKE.decrypt(C,SK)
(r || k)=G2(PKH || M)
if C == PKE.encrypt(M,PK,r):
  return K0 = F(C || k)
else:
  return K1 = F(C || s)
```
To guarantee constant-time execution, we may need to calculate both `K0` and `K1` before branching.
