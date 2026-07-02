# Peaks far over the 64 MiB limit. With a per-run cgroup the kernel OOM-kills
# it at 1.25x the cap and the measured memory.peak decides MLE; without one
# (degraded host) RLIMIT_AS turns this into a MemoryError -> RE instead.
x = bytearray(256 * 1024 * 1024)
a, b = map(int, input().split())
print(a + b)
