# Loops forever. tallyrun kills it when it reaches the instruction budget, so
# the verdict comes quickly and doesn't depend on machine load.
i = 0
while True:
    i += 1
