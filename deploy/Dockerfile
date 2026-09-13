# Reference image: the tallyrun binary + bubblewrap + toolchains, with tini as
# PID 1 (reaps the foreign children bwrap reparents on exit). Run it with
# cgroup delegation (deploy/compose.yml) for full accounting; instruction
# counting additionally needs a PMU and a seccomp profile that allows
# perf_event_open (the default Docker profile blocks it).
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
# The smoke test greets on stderr: tallyrun's stdout carries the JSON result
# and the sandboxed program is not allowed to share it.
CMD ["tallyrun", "run", "--no-isolate", "--", "python3", "-c", "import sys; print('tallyrun ready', file=sys.stderr)"]
