# Reference image: tallyrun, bubblewrap and toolchains, with tini as PID 1 to
# reap the processes reparented to it when bwrap exits. Run it with cgroup
# delegation (deploy/compose.yml) for full accounting. Instruction counting
# also needs a PMU and a seccomp profile that allows perf_event_open, which
# Docker's default profile blocks.
FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        bubblewrap \
        g++ \
        tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/tallyrun /usr/local/bin/tallyrun

ENTRYPOINT ["tini", "--"]
# The smoke test prints to stderr because tallyrun's stdout carries the JSON
# result, and the program can't write there.
CMD ["tallyrun", "run", "--no-isolate", "--", "python3", "-c", "import sys; print('tallyrun ready', file=sys.stderr)"]
