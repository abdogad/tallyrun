# Interpreter-bound arithmetic — the typical accepted-solution shape.
s = 0
for i in range(2_000_000):
    s += i * i
print(s)
