# String-keyed dict churn — maximally sensitive to CPython hash randomization:
# every str hash, bucket order, and collision chain depends on PYTHONHASHSEED.
# Run with the seed pinned and unpinned to isolate that effect.
d = {}
for i in range(300_000):
    d[str(i)] = i
s = 0
for i in range(300_000):
    s += d[str(i)]
print(s)
