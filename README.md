# linkg16

This library implements the LinkG16 algorithm defined in [zk-creds](https://eprint.iacr.org/2022/878). Given a set of Groth16 proofs with some common public input, this algorithm proves that the proofs indeed share the common input _without_ revealing the input itself. This is called a "linkage" proof in the paper.

## Usage

See the test code in [link.rs](src/link.rs). It forms three distinct circuits: one computes `H(domain_str1, k1)`, one computes, `H(H(domain_str2, k1), k2)`, and one computes `H(domain_str1, k2)`. The `link` procedure proves these circuits share the same `k1, k2`.

## License

All code is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
