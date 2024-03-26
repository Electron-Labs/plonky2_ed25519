## plonky2 Ed25519

Contains Plonky2 implementation of [Ed25519 signature scheme](https://datatracker.ietf.org/doc/html/rfc8032#section-6)

Command (Runs basic benchmark) : 
```console
RUSTFLAGS=-Ctarget-cpu=native cargo run --package plonky2_ed25519 --bin plonky2_ed25519 --release
```

M2 Macbook Air Performance:
```
Building ed25519 circuit with 177103 gates
Time taken to build the circuit : 11.305351375s
Time taken to generate the proof : 32.186048458s
Time taken to verify the proof : 5.075916ms
```

## Developer chat
In case you wish to contribute or collaborate, you can join our ZK builder chat at - https://t.me/+GRX2LF9YSEwyNjQ1
