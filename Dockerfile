FROM rust:1.91-bookworm AS build

COPY ./src /src
COPY ./Cargo.toml /Cargo.toml
COPY ./Cargo.lock /Cargo.lock

RUN cargo build --bin smp-poc

FROM scratch

COPY --from=build /target/debug/smp-poc /smp-poc
COPY --from=build /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6
COPY --from=build /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/libgcc_s.so.1
COPY --from=build /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2
