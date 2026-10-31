# Machine environment

- Host: `<host>`
- OS: Ubuntu 24.04.3 LTS
- Kernel: Linux 6.8.0-90-generic
- Architecture: AArch64 (`aarch64`)
- Processor: HiSilicon Kunpeng-920
- Available CPUs: 32, one hardware thread per reported core
- Benchmark affinity: CPU 31 only; conditions ran sequentially
- NUMA nodes: 1
- Memory: 62 GiB installed, no swap
- Python: 3.12.3, GCC 13.3.0 build
- libc: glibc 2.39
- Page size: 4,096 bytes

The host did not expose a CPU-frequency value through `lscpu` or the Linux
`cpufreq` sysfs interface, so no clock rate is reported. Filesystem caches were
not flushed between randomized conditions.
