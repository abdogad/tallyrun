# String-keyed dict churn. Every str hash, bucket order and collision chain
# depends on PYTHONHASHSEED, so this is as sensitive to hash randomization as
# CPython code gets. The benchmark runs it with the seed pinned and unpinned.
d = {}
for i in range(300_000):
    d[str(i)] = i
s = 0
for i in range(300_000):
    s += d[str(i)]
print(s)
