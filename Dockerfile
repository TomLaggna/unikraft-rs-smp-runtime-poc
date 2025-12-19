FROM rust:1.91-bookworm AS build

# Install required tools
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Copy source files
COPY ./.cargo ./.cargo
COPY ./src ./src
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./Makefile ./Makefile

# Install musl target
RUN rustup target add x86_64-unknown-linux-musl

# Build Rust application
RUN cargo build --release --target x86_64-unknown-linux-musl --bin smp-poc

# Create final image with binary and dependencies
FROM scratch

COPY --from=build /target/x86_64-unknown-linux-musl/release/smp-poc /smp-poc
COPY --from=build /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6
COPY --from=build /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/libgcc_s.so.1
COPY --from=build /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2
