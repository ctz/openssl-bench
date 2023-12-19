# OpenSSL bench

This repository provides benchmarks that measure the throughput and memory footprint you get from
OpenSSL 3.x. They have been used in the past to compare performance against
[rustls](https://github.com/rustls/rustls) (see the results of [December
2023](https://github.com/aochagavia/rustls-bench-results) and [July
2019](https://jbp.io/2019/07/01/rustls-vs-openssl-performance.html)).

The measured aspects are:

1. Bulk data transfer throughput in MiB/s;
2. Handshake throughput (full, session id, tickets) in handshakes per second;
3. Memory usage per connection.

## Building

The code expects a built OpenSSL tree in `../openssl/` and the rustls repository in `../rustls`.

## Running

- `make measure`: runs bulk transfer and handshake throughput benchmarks using a predefined list of
  cipher suites.
- `make memory`: measures memory usage for different amounts of connections.

We usually extend the duration of the benchmarks in an attempt to neutralize the effect of cold CPU
and page caches, giving us more accurate results. This is done through the `BENCH_MULTIPLIER`
environment variable, which tells the benchmark runner to multiply the amount of work done. For
instance, `BENCH_MULTIPLIER=8` will ensure we do 8 times the work.
