# Makefile for Rust Multicore with Assembly Boot Code
# Target: Unikraft on KVM/QEMU x86_64

# Configuration
RUST_TARGET := x86_64-unknown-linux-musl
CARGO := cargo
GCC := gcc
QEMU := qemu-system-x86_64
KRAFT := kraft

# Directories
SRC_DIR := src
BOOT_DIR := $(SRC_DIR)/boot
TARGET_DIR := target/$(RUST_TARGET)/release
BUILD_DIR := build
UNIKRAFT_DIR := .unikraft
KERNEL_DIR := base_kernel

# Assembly source and object
ASM_SRC := $(BOOT_DIR)/boot_trampoline.S
ASM_HDR := $(BOOT_DIR)/boot_defs.h
ASM_OBJ := $(BUILD_DIR)/boot_trampoline.o
ASM_LIB := $(BUILD_DIR)/libboot_trampoline.a

# Final binary
BINARY := $(TARGET_DIR)/smp-poc
KERNEL := $(KERNEL_DIR)/kernel
INITRD := $(UNIKRAFT_DIR)/build/initramfs-x86_64.cpio

# GCC flags for assembly compilation
ASFLAGS := -c \
           -m64 \
           -nostdlib \
           -fno-pic \
           -fno-stack-protector \
           -mno-red-zone \
           -I$(BOOT_DIR)

# QEMU flags (from README.md - adjusted for SMP PoC)
QEMU_FLAGS := -kernel $(KERNEL) \
              -initrd $(INITRD) \
              -machine pc,accel=kvm \
              -cpu host,+x2apic,-pmu \
              -m 953M \
              -smp cpus=4 \
              -nographic -no-reboot -parallel none \
              -rtc base=utc \
              -append 'vfs.fstab=[ "initrd0:/:extract:::" ] env.vars=[ "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ] -- /smp-poc'

.PHONY: all asm rust build-initrd run debug clean help buildkit

# Default target
all: asm rust

# Build boot trampoline assembly (without PIE - it's position-dependent by design)
asm: $(ASM_LIB)
	@echo "✓ Assembly library ready: $(ASM_LIB)"

$(ASM_OBJ): $(ASM_SRC) $(ASM_HDR)
	@mkdir -p $(BUILD_DIR)
	@echo "Compiling boot trampoline assembly..."
	$(GCC) $(ASFLAGS) -o $@ $(ASM_SRC)

$(ASM_LIB): $(ASM_OBJ)
	@echo "Creating static library..."
	ar rcs $@ $<

# Build Rust application (links to assembly library)
rust: asm
	@echo "Building Rust application..."
	$(CARGO) build --release --target $(RUST_TARGET)
	@echo "✓ Rust build complete: $(BINARY)"

# Build initramfs using kraft
build-initrd: rust buildkit
	@echo "Building initramfs with kraft..."
	$(KRAFT) build --plat qemu --arch x86_64
	@echo "✓ Initramfs created: $(INITRD)"

# Setup buildkit containe
# if the buildkitd container is not set up on this system, run this:
# docker run -d --name buildkitd --privileged moby/buildkit:latest
buildkit:
	@echo "Starting buildkitd container..."
	@if ! docker ps | grep -q buildkitd; then \
		docker start buildkitd; \
	fi
	@export KRAFTKIT_BUILDKIT_HOST=docker-container://buildkitd
	@echo "✓ buildkitd running. Exported: KRAFTKIT_BUILDKIT_HOST=docker-container://buildkitd"

# Run in QEMU
run: build-initrd
	@echo "Starting QEMU with 4 CPUs and Unikraft kernel..."
	@if [ ! -f $(KERNEL) ]; then \
		echo "Error: Kernel not found at $(KERNEL)"; \
		exit 1; \
	fi
	@if [ ! -f $(INITRD) ]; then \
		echo "Error: Initramfs not found at $(INITRD)"; \
		exit 1; \
	fi
	$(QEMU) $(QEMU_FLAGS)

# Run with GDB support
debug: all
	@echo "Starting QEMU with GDB server on port 1234..."
	$(QEMU) $(QEMU_FLAGS) -s -S &
	@echo "Connect with: gdb -ex 'target remote :1234' $(KERNEL)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(CARGO) clean
	rm -rf $(BUILD_DIR)
	@echo "✓ Clean complete"

# Help target
help:
	@echo "Unikraft Rust Multicore - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build Rust application (default)"
	@echo "  rust         - Build Rust application with embedded assembly"
	@echo "  build-initrd - Build initramfs with kraft (requires rust)"
	@echo "  buildkit     - Start buildkitd Docker container"
	@echo "  run          - Build and run in QEMU with Unikraft kernel"
	@echo "  debug        - Run with GDB server on port 1234"
	@echo "  clean        - Remove all build artifacts"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Configuration:"
	@echo "  Target:  $(RUST_TARGET)"
	@echo "  CPUs:    4 (adjust with -smp cpus=N in QEMU_FLAGS)"
	@echo "  Memory:  953M"
	@echo "  Kernel:  $(KERNEL)"
	@echo "  Initrd:  $(INITRD)"
	@echo ""
	@echo "Requirements:"
	@echo "  - Rust toolchain with $(RUST_TARGET) target"
	@echo "  - GCC (for assembly compilation)"
	@echo "  - kraft (Unikraft build tool)"
	@echo "  - QEMU (qemu-system-x86_64)"
	@echo "  - Docker (for buildkit)"
	@echo "  - KVM support (recommended)"
	@echo ""
	@echo "Environment Variables:"
	@echo "  KRAFTKIT_BUILDKIT_HOST=docker-container://buildkitd"
	@echo "  KRAFTKIT_TARGET=smp-poc"
