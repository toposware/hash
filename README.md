# hash

This crate provides an ongoing implementation of algebraic cryptographic hash functions.

* This implementation can be used in `no-std` environments by relying on the `alloc` crate instead.

It currently contains:
- an instantiation of Rescue-Prime over a 252-bit prime field with state width 4 and capacity 2
- an instantiation of Rescue-Prime over a 63-bit prime field with state width 14 and capacity 7