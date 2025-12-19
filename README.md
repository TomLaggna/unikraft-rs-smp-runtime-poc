# Rust "SMP PoC!"

This directory contains a Rust "Hello, World!" example running on Unikraft.

To run this example, install [Unikraft's companion command-line toolchain `kraft`](https://unikraft.org/docs/cli) and [the `nightly` Rust toolchain channel through Rustup](https://www.rust-lang.org/tools/install).

## Build

To build the image, clone this repository and `cd` into this directory.
You can then build the project with:

```bash
KRAFTKIT_TARGET=smp-poc cargo +nightly build -Z build-std=std,panic_abort --target x86_64-unikraft-linux-musl
```

In the above command, `KRAFTKIT_TARGET=helloworld` makes the name of the application known to `kraftld`.
Rust for Unikraft currently only supports the `qemu/x86_64` target.
If a `Kraftfile` contains more targets, the correct one can be selected through the `KRAFTKIT_PLAT` and `KRAFTKIT_ARCH` environment variables.

## Run

In order to run the locally built image, use `kraft`:

```bash
kraft run --rm --plat qemu --arch x86_64 .
```

It will print out a "Hello, World!" message.

## Learn more

- [How to build unikernels](https://unikraft.org/docs/cli/building)
- [How to run unikernels locally](https://unikraft.org/docs/cli/running)
- [The `Kraftfile` specification](https://unikraft.org/docs/cli/reference/kraftfile/latest)
- [`*-unikraft-linux-musl` - The `rustc` book](https://doc.rust-lang.org/rustc/platform-support/unikraft-linux-musl.html)

## SMP
Sources:
- https://unikraft.org/blog/2022-08-20-unikraft-releases-phoebe#testing
- https://unikraft.org/blog/2022-06-13-unikraft-releases-hyperion#implementing-the-api-for-a-new-architecture

Conclusions:
- requires additional Kraftfile configuration
- requires additional cores started up by QEMU
- requires access to the unikraft internal API (no rust bindings? -> have to use FFI?)

```qemu-system-x86_64 \
  -kernel base_kernel/kernel \
  -initrd .unikraft/build/initramfs-x86_64.cpio \
  -machine pc,accel=kvm \
  -cpu host,+x2apic,-pmu \
  -m 953M \
  -smp cpus=3 \
  -device virtio-net-pci,mac=02:b0:b0:d3:d2:01,netdev=hostnet0 \
  -netdev user,id=hostnet0,hostfwd=tcp::8080-:8080 \
  -nographic -no-reboot -parallel none \
  -rtc base=utc \
  -append 'vfs.fstab=[ "initrd0:/:extract:::" ] env.vars=[ "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ] -- /smp-poc'```