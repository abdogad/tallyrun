# Burns instructions forever; runbox kills it at the instruction budget
# (~5 ms poll), so the verdict lands promptly and load-invariantly.
i = 0
while True:
    i += 1
