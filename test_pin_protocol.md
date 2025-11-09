# Testing PIN Protocol with Virtual Authenticator

This guide shows how to test the PIN protocol implementation using the virtual authenticator
example.

## Prerequisites

1. **Linux with UHID support**: The virtual authenticator uses the Linux UHID kernel module
2. **Proper permissions**: Run the setup commands below as root

```bash
# Create a new group called fido
getent group fido || (groupadd fido && usermod -a -G fido $USER)

# Add uhid to the list of modules to load during boot
echo "uhid" > /etc/modules-load.d/fido.conf

# Create a udev rule that allows all users that belong to the group fido to access /dev/uhid
echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' > /etc/udev/rules.d/90-uinput.rules
udevadm control --reload-rules && udevadm trigger

# Load the uhid module now (without rebooting)
modprobe uhid

# You may need to log out and log back in for group membership to take effect
```

## Testing Steps

### Step 1: Start the Virtual Authenticator

The authenticator example creates a virtual FIDO2 device with PIN "123456":

```bash
cargo run --example authenticator
```

You should see:

```
Configuring authenticator with PIN: 123456
PIN hash configured: [8d, 96, 9e, ef, 6e, ca, d3, c2]...

Authenticator is running!
Listening for USB HID messages...
Press Ctrl+C to stop
```

**Keep this running in one terminal.**

### Step 2: Run the PIN Protocol Client (in a new terminal)

The PIN protocol example attempts to establish key agreement and retrieve a PIN token:

```bash
cargo run --example pin_protocol
```

Expected output:

```
PIN Protocol Example
===================

Enumerating transports...
Found 1 transport(s)
Opening transport...
Transport opened successfully!

Establishing key agreement with protocol V2...
Key agreement successful!
Platform public key (first 16 bytes): [04, ad, 5e, 29, ...]...

Attempting to get PIN token...
Note: Replace '123456' with your actual authenticator PIN
[SUCCESS] Got PIN token with permissions
Token (first 16 bytes): [xx, xx, xx, ...]...

Example completed!
```

## How It Works

1. **Virtual Authenticator Setup**:

   - The `authenticator.rs` example calls `Authenticator::set_pin_hash()` with the SHA-256 hash of
     "123456"
   - This configures the authenticator to accept PIN authentication
   - The authenticator creates a virtual USB HID device via UHID

2. **PIN Protocol Flow**:

   - The `pin_protocol.rs` example enumerates USB HID devices and finds the virtual authenticator
   - It establishes ECDH key agreement using PIN protocol V2
   - It sends the PIN "123456" encrypted using the shared secret
   - The authenticator decrypts and verifies the PIN hash
   - If correct, it returns a PIN/UV auth token that can be used for subsequent operations

3. **Security**:
   - The PIN is never transmitted in plaintext
   - All PIN operations use encrypted channels via ECDH
   - The authenticator stores only the SHA-256 hash of the PIN

## Troubleshooting

### "Failed to enumerate transports"

- Ensure the authenticator example is running
- Check that UHID module is loaded: `lsmod | grep uhid`
- Verify permissions: `ls -l /dev/uhid`

### "Permission denied" on /dev/uhid

- Run the setup commands above as root
- Log out and log back in after adding yourself to the `fido` group
- Verify group membership: `groups | grep fido`

### "getPinToken failed: error.ctap2_err_pin_invalid"

- The PIN in the example is hardcoded as "123456"
- Both examples must use the same PIN
- Check that `get_pin_hash()` in both examples produces the same hash

## Next Steps

After successful PIN protocol testing, you can:

1. Test credential creation with PIN/UV authentication
2. Test credential assertion (getAssertion) operations
3. Test credential management operations
4. Implement real user interaction for UP and UV callbacks
