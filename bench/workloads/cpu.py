# Interpreter-bound arithmetic, shaped like a typical accepted solution.
s = 0
for i in range(2_000_000):
    s += i * i
print(s)
