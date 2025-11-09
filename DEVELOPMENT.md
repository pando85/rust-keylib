# Development Guide

## Building the Project

### Using Prebuilt Libraries (Recommended for Users)

The easiest way to use rust-keylib is with the `bundled` feature:

```toml
[dependencies]
keylib = { version = "0.1", features = ["bundled"] }
```

This automatically downloads prebuilt native libraries for your platform during `cargo build`,
eliminating the need to install:

- Zig compiler
- libudev-dev (on Linux)
- Build tools

### Building from Source (Recommended for Contributors)

For development work, you'll want to build from source to make changes to the underlying keylib:

1. **Install dependencies:**

   ```bash
   # Ubuntu/Debian
   sudo apt-get install libudev-dev

   # Install Zig from https://ziglang.org/download/
   # Or use your package manager
   ```

2. **Clone with submodules:**

   ```bash
   git clone --recurse-submodules https://github.com/pando85/rust-keylib
   # Or if already cloned:
   git submodule update --init
   ```

3. **Build:**

   ```bash
   cargo build
   ```

### Creating Prebuilt Artifacts

Maintainers can trigger prebuilt artifact creation:

1. **Automated on Release:** When you create a GitHub release, the `prebuilt.yml` workflow
   automatically builds and attaches artifacts for supported platforms.

2. **Manual Trigger:**

   Go to Actions → "Build Prebuilt Artifacts" → "Run workflow" and specify the version tag.

3. **Local Build:**

   ```bash
   cd keylib-sys/keylib
   zig build install

   # Package artifacts
   mkdir -p prebuilt/lib prebuilt/include
   cp zig-out/lib/libkeylib.a prebuilt/lib/
   cp zig-out/lib/libuhid.a prebuilt/lib/
   cp bindings/c/include/keylib.h prebuilt/include/
   cp bindings/linux/include/uhid.h prebuilt/include/

   tar czf keylib-prebuilt-$(rustc -vV | grep host | cut -d' ' -f2).tar.gz -C prebuilt .
   sha256sum keylib-prebuilt-*.tar.gz > keylib-prebuilt-*.tar.gz.sha256
   ```

## End-to-End WebAuthn Testing

The `e2e_webauthn_test.rs` test file provides comprehensive end-to-end testing of the complete
WebAuthn/FIDO2 flow, including:

1. **Virtual Authenticator**: A software authenticator running in a background thread
2. **PIN Protocol**: Full PIN/UV authentication with protocol V2
3. **Registration Flow**: Complete makeCredential operation
4. **Authentication Flow**: Complete getAssertion operation
5. **UHID Transport**: Virtual USB HID device for testing without physical hardware

## Architecture

```ascii
┌──────────────────────────────────────────────────────────────┐
│                      Test Process                            │
│                                                               │
│  ┌────────────────────┐         ┌────────────────────┐      │
│  │  Test Thread       │         │  Authenticator     │      │
│  │  (Client)          │         │  Thread            │      │
│  │                    │         │                    │      │
│  │  ┌──────────────┐  │         │  ┌──────────────┐ │      │
│  │  │   Client     │  │         │  │ Authenticator│ │      │
│  │  │   Builder    │  │         │  │  + Callbacks │ │      │
│  │  │   API        │  │         │  └──────┬───────┘ │      │
│  │  └──────┬───────┘  │         │         │         │      │
│  │         │          │         │  ┌──────▼───────┐ │      │
│  │  ┌──────▼───────┐  │         │  │   CTAP HID   │ │      │
│  │  │  Transport   │  │         │  └──────┬───────┘ │      │
│  │  │  (USB HID)   │  │         │         │         │      │
│  │  └──────┬───────┘  │         │  ┌──────▼───────┐ │      │
│  │         │          │         │  │     UHID     │ │      │
│  └─────────┼──────────┘         │  │   (write)    │ │      │
│            │                    │  └──────────────┘ │      │
│            │                    └────────────────────┘      │
│            │                             ▲                  │
│            └─────────────────────────────┘                  │
│                    /dev/uhid                                │
└──────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Authenticator Thread**:

   - Creates a virtual UHID device (`/dev/uhid`)
   - Runs CTAP HID protocol handler
   - Processes CTAP2 commands via software authenticator
   - Stores credentials in memory (HashMap)

2. **Test Thread (Client)**:

   - Enumerates USB HID devices (finds the virtual authenticator)
   - Opens transport connection
   - Sends CTAP2 commands using the Client builder API
   - Receives responses through the transport

3. **Communication**:
   - Both threads communicate through the Linux UHID kernel module
   - UHID provides a `/dev/uhid` device that appears as a real USB HID device
   - The OS handles the transport layer, making it indistinguishable from hardware

## Prerequisites

### Linux Kernel Requirements

The tests require the UHID kernel module and proper permissions:

```bash
# Load the UHID kernel module
sudo modprobe uhid

# Create fido group
sudo groupadd fido 2>/dev/null || true

# Add your user to the fido group
sudo usermod -a -G fido $USER

# Create udev rules for UHID access
echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' | \
    sudo tee /etc/udev/rules.d/90-uhid.rules

# Reload udev rules
sudo udevadm control --reload-rules && sudo udevadm trigger

# You'll need to log out and log back in for group membership to take effect
```

### Verify Setup

```bash
# Check if UHID module is loaded
lsmod | grep uhid

# Check if /dev/uhid exists and has correct permissions
ls -l /dev/uhid

# Should show: crw-rw---- 1 root fido ... /dev/uhid
```

## Running the Tests

### Compile the Tests

```bash
make test-e2e
```
