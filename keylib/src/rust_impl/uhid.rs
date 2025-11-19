//! Pure Rust UHID Support
//!
//! Provides UHID (Userspace HID) device support matching the zig-ffi API.

use crate::common::{Error, Result};

#[cfg(target_os = "linux")]
use keylib_transport::UhidDevice;

/// UHID virtual device wrapper (matches zig-ffi API)
#[cfg(target_os = "linux")]
pub struct Uhid {
    device: UhidDevice,
}

#[cfg(target_os = "linux")]
impl Uhid {
    /// Open a UHID device
    ///
    /// Creates a virtual FIDO2 HID device via Linux UHID interface.
    pub fn open() -> Result<Self> {
        println!("[UHID] Creating virtual FIDO2 device...");
        let device = UhidDevice::create_fido_device().map_err(|e| {
            eprintln!("[UHID] ✗ Failed to create UHID device: {:?}", e);
            Error::Other
        })?;

        println!("[UHID] ✓ Virtual FIDO2 device created successfully");
        println!("[UHID] Device should appear as /dev/hidrawN");
        println!("[UHID] Waiting for HID packets from clients...");

        Ok(Self { device })
    }

    /// Read a 64-byte HID packet
    ///
    /// Returns the number of bytes read (0 if no data available).
    /// Non-blocking: returns immediately if no packet is available.
    pub fn read_packet(&self, out: &mut [u8; 64]) -> Result<usize> {
        match self.device.read_packet(out) {
            Ok(Some(len)) => {
                println!(
                    "[UHID] ← Read {} bytes: {}",
                    len,
                    hex::encode(&out[..len.min(16)])
                );
                Ok(len)
            }
            Ok(None) => Ok(0), // No packet available
            Err(e) => {
                eprintln!("[UHID] ✗ Read error: {:?}", e);
                Err(Error::Other)
            }
        }
    }

    /// Write a 64-byte HID packet
    ///
    /// Returns the number of bytes written (always 64 on success).
    pub fn write_packet(&self, data: &[u8; 64]) -> Result<usize> {
        println!(
            "[UHID] → Write 64 bytes: {}",
            hex::encode(&data[..16.min(data.len())])
        );

        self.device.write_packet(data).map_err(|e| {
            eprintln!("[UHID] ✗ Write error: {:?}", e);
            Error::Other
        })?;

        println!("[UHID] ✓ Write successful");
        Ok(64) // Return number of bytes written
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires /dev/uhid permissions
    fn test_uhid_creation() {
        // This test requires proper permissions
        // Run with: cargo test -- --ignored
        let _uhid = Uhid::open();
    }
}
