//! Pure Rust Transport Layer
//!
//! Provides USB HID and UHID transports with an API matching the zig-ffi implementation.

use crate::common::{Error, Result};

#[cfg(all(feature = "pure-rust", feature = "usb"))]
use keylib_transport::{enumerate_devices, init_usb, UsbDeviceInfo, UsbTransport as RawUsbTransport};

#[cfg(all(feature = "pure-rust", target_os = "linux"))]
use keylib_transport::UhidDevice;

use keylib_transport::{ChannelManager, CtapHidHandler, CommandHandler, Message, Packet};

use std::sync::{Arc, Mutex};

/// Safe Rust wrapper for Transport
///
/// Matches the API of the zig-ffi Transport type.
pub struct Transport {
    inner: Arc<Mutex<TransportInner>>,
}

enum TransportInner {
    #[cfg(all(feature = "pure-rust", feature = "usb"))]
    Usb {
        transport: RawUsbTransport,
        channel_manager: ChannelManager,
        opened: bool,
    },
    #[cfg(all(feature = "pure-rust", target_os = "linux"))]
    Uhid {
        device: UhidDevice,
        channel_manager: ChannelManager,
        opened: bool,
    },
}

impl Transport {
    #[cfg(all(feature = "pure-rust", feature = "usb"))]
    fn from_usb(transport: RawUsbTransport) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TransportInner::Usb {
                transport,
                channel_manager: ChannelManager::new(),
                opened: false,
            })),
        }
    }

    #[cfg(all(feature = "pure-rust", target_os = "linux"))]
    fn from_uhid(device: UhidDevice) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TransportInner::Uhid {
                device,
                channel_manager: ChannelManager::new(),
                opened: false,
            })),
        }
    }

    /// Open the transport for communication
    pub fn open(&mut self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        match &mut *inner {
            #[cfg(all(feature = "pure-rust", feature = "usb"))]
            TransportInner::Usb { transport, opened, .. } => {
                if *opened {
                    return Ok(());
                }
                transport.open().map_err(|e| Error::IoError(e.to_string()))?;
                *opened = true;
                Ok(())
            }
            #[cfg(all(feature = "pure-rust", target_os = "linux"))]
            TransportInner::Uhid { opened, .. } => {
                // UHID devices are always "open" after creation
                *opened = true;
                Ok(())
            }
        }
    }

    /// Close the transport
    pub fn close(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        match &mut *inner {
            #[cfg(all(feature = "pure-rust", feature = "usb"))]
            TransportInner::Usb { transport, opened, .. } => {
                if *opened {
                    let _ = transport.close();
                    *opened = false;
                }
            }
            #[cfg(all(feature = "pure-rust", target_os = "linux"))]
            TransportInner::Uhid { opened, .. } => {
                *opened = false;
            }
        }
    }

    /// Write data to the transport
    ///
    /// This sends raw packets. For CTAP commands, use send_ctap_command instead.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        match &mut *inner {
            #[cfg(all(feature = "pure-rust", feature = "usb"))]
            TransportInner::Usb { transport, .. } => {
                transport
                    .write(data)
                    .map_err(|e| Error::IoError(e.to_string()))?;
                Ok(())
            }
            #[cfg(all(feature = "pure-rust", target_os = "linux"))]
            TransportInner::Uhid { device, .. } => {
                // UHID requires exactly 64 bytes
                if data.len() != 64 {
                    return Err(Error::Other);
                }
                let mut packet = [0u8; 64];
                packet.copy_from_slice(data);
                device
                    .write_packet(&packet)
                    .map_err(|e| Error::IoError(e.to_string()))?;
                Ok(())
            }
        }
    }

    /// Read data from the transport with timeout
    pub fn read(&mut self, buffer: &mut [u8], timeout_ms: i32) -> Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        match &mut *inner {
            #[cfg(all(feature = "pure-rust", feature = "usb"))]
            TransportInner::Usb { transport, .. } => {
                let result = transport
                    .read(buffer, timeout_ms as u64)
                    .map_err(|e| Error::IoError(e.to_string()))?;
                Ok(result)
            }
            #[cfg(all(feature = "pure-rust", target_os = "linux"))]
            TransportInner::Uhid { device, .. } => {
                // UHID requires exactly 64 bytes buffer
                if buffer.len() < 64 {
                    return Err(Error::Other);
                }
                let mut packet = [0u8; 64];
                // UHID doesn't have timeout, use blocking read
                if let Some(len) = device
                    .read_packet(&mut packet)
                    .map_err(|e| Error::IoError(e.to_string()))? {
                    buffer[..len].copy_from_slice(&packet[..len]);
                    Ok(len)
                } else {
                    Ok(0)
                }
            }
        }
    }

    /// Send a CTAP command and receive response
    ///
    /// This handles CTAP HID framing automatically.
    pub fn send_ctap_command(&mut self, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        use keylib_transport::Cmd;

        // Convert u8 to Cmd enum
        let cmd_enum = Cmd::from_u8(cmd).ok_or(Error::Other)?;

        // Get or allocate channel
        let mut inner = self.inner.lock().unwrap();
        let channel_id = match &mut *inner {
            #[cfg(all(feature = "pure-rust", feature = "usb"))]
            TransportInner::Usb { .. } => {
                // Use broadcast channel for INIT, otherwise allocate
                if cmd == 0x06 { // CTAPHID_INIT
                    0xffffffff
                } else {
                    // For this simplified implementation, use a fixed channel
                    // In a full implementation, would do INIT handshake first
                    0x01000000
                }
            }
            #[cfg(all(feature = "pure-rust", target_os = "linux"))]
            TransportInner::Uhid { .. } => {
                if cmd == 0x06 {
                    0xffffffff
                } else {
                    0x01000000
                }
            }
        };

        // Build CTAP HID message
        let message = Message::new(channel_id, cmd_enum, data.to_vec());

        // Fragment into packets
        let packets = message.to_packets().map_err(|_| Error::Other)?;

        // Send packets
        for packet in &packets {
            let packet_bytes = packet.as_bytes();
            drop(inner); // Release lock before write
            self.write(packet_bytes)?;
            inner = self.inner.lock().unwrap();
        }

        // Read response packets
        let mut response_packets = Vec::new();

        loop {
            drop(inner); // Release lock before read
            let mut buffer = [0u8; 64];
            let bytes_read = self.read(&mut buffer, 5000)?;
            inner = self.inner.lock().unwrap();

            if bytes_read == 0 {
                return Err(Error::Timeout);
            }

            // Parse packet
            let packet = Packet::from_bytes(buffer);

            // Check channel matches
            if packet.cid() != channel_id {
                continue; // Wrong channel, ignore
            }

            // Check for errors
            if let Some(cmd) = packet.cmd() {
                if matches!(cmd, Cmd::Error) {
                    return Err(Error::Other);
                }
            }

            response_packets.push(packet);

            // Check if we have all packets
            if let Some(first) = response_packets.first() {
                if let Some(total_len) = first.payload_len() {
                    let mut received_len = first.payload().len();

                    for pkt in &response_packets[1..] {
                        received_len += pkt.payload().len();
                    }

                    if received_len >= total_len as usize {
                        break;
                    }
                }
            }
        }

        // Reassemble message
        let response_message = Message::from_packets(&response_packets)
            .map_err(|_| Error::Other)?;

        Ok(response_message.data)
    }

    /// Get a description of the transport
    pub fn get_description(&self) -> Result<String> {
        let inner = self.inner.lock().unwrap();
        match &*inner {
            #[cfg(all(feature = "pure-rust", feature = "usb"))]
            TransportInner::Usb { .. } => {
                Ok("USB HID Transport".to_string())
            }
            #[cfg(all(feature = "pure-rust", target_os = "linux"))]
            TransportInner::Uhid { .. } => Ok("UHID Virtual Device".to_string()),
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.close();
    }
}

/// Safe Rust wrapper for TransportList
///
/// Matches the API of the zig-ffi TransportList type.
pub struct TransportList {
    transports: Vec<Transport>,
}

impl TransportList {
    /// Enumerate all available transports
    pub fn enumerate() -> Result<Self> {
        #[allow(unused_mut)]
        let mut transports = Vec::new();

        #[cfg(all(feature = "pure-rust", feature = "usb"))]
        {
            // Initialize USB library
            if let Ok(()) = init_usb() {
                // Enumerate USB FIDO devices
                if let Ok(devices) = enumerate_devices() {
                    for device_info in devices {
                        if let Ok(transport) = RawUsbTransport::new(device_info) {
                            transports.push(Transport::from_usb(transport));
                        }
                    }
                }
            }
        }

        Ok(TransportList { transports })
    }

    /// Get the number of transports
    pub fn len(&self) -> usize {
        self.transports.len()
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.transports.is_empty()
    }

    /// Get a transport at the given index
    pub fn get(&self, index: usize) -> Option<Transport> {
        self.transports.get(index).map(|t| Transport {
            inner: Arc::clone(&t.inner),
        })
    }

    /// Iterate over all transports
    pub fn iter(&self) -> impl Iterator<Item = Transport> + '_ {
        self.transports.iter().map(|t| Transport {
            inner: Arc::clone(&t.inner),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_list_enumerate() {
        // Should not panic even if no devices available
        let list = TransportList::enumerate();
        assert!(list.is_ok());
    }
}
