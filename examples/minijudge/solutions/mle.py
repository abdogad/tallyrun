# Allocates far more than the 64 MiB limit. With a cgroup the kernel OOM-kills
# it at 1.25x the limit and memory.peak gives MLE. Without one, RLIMIT_AS
# makes the allocation raise MemoryError and the verdict is RE.
x = bytearray(256 * 1024 * 1024)
a, b = map(int, input().split())
print(a + b)
