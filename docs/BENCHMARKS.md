# Benchmarks

```bash
sbm-lab benchmark --profile aarch64-uefi --runs 10 --output bench.json
```

The metric is host milliseconds from QEMU start until the guest prints `efi-launched`. The JSON schema is `sbm-lab.benchmark.v1`.

- `execution_class` is `accelerated_virtualization` for HVF and KVM, and `emulation` for TCG.
- `representative_of_physical_hardware` is false for every lab run.
- `methodology_complete` is true only when the sample count is at least 10.
- The default `--runs 3` is a smoke sample. Do not quote it as a benchmark.
- A TCG sample is not a physical x86 measurement, including when the guest architecture matches the host.

Percentiles use index `round(percent/100 * (n - 1))` on the sorted samples. Do not invent numbers. Archive a real `bench.json` under `research/validation/evidence/` before citing one.

The summary fields are `n`, `min_ms`, `p50_ms`, `p95_ms`, and `max_ms`.
