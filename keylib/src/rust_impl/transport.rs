//! Pure Rust Transport Layer
//!
//! Provides access to USB HID and UHID transports.

#[cfg(feature = "pure-rust")]
pub use keylib_transport::{
    ChannelManager, Cmd, CtapHidHandler, Message, Packet, CommandHandler,
};

#[cfg(all(feature = "pure-rust", target_os = "linux"))]
pub use keylib_transport::UhidDevice;

#[cfg(all(feature = "pure-rust", feature = "usb"))]
pub use keylib_transport::{
    enumerate_devices, init_usb, AuthenticatorRunner, UsbDeviceInfo, UsbTransport,
};
