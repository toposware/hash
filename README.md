# hash

This crate provides an ongoing implementation of algebraic cryptographic hash functions.

* This implementation can be used in `no-std` environments by relying on the `alloc` crate instead.

It currently contains:
- an instantiation of Rescue-Prime over a 63-bit prime field with state width 8 and capacity 4
- an instantiation of Rescue-Prime over a 63-bit prime field with state width 14 and capacity 7

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
