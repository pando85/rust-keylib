//! Custom CTAP command support
//!
//! This module provides support for vendor-specific custom CTAP commands
//! that extend the standard CTAP2 protocol.

use std::sync::Arc;

/// Handler function for a custom CTAP command
///
/// # Arguments
///
/// * `auth` - Opaque pointer to the authenticator instance
/// * `request` - The CTAP request bytes (command byte + CBOR parameters)
/// * `response` - Buffer to write the response into (up to 7609 bytes)
///
/// # Returns
///
/// The length of the response written into the buffer, or 0 if the command failed.
///
/// # Safety
///
/// The handler must not write more than `response.len()` bytes to the response buffer.
/// The authenticator pointer should not be dereferenced directly - it's only for
/// internal use by the Zig keylib.
pub type CustomCommandHandler =
    Arc<dyn Fn(*mut std::ffi::c_void, &[u8], &mut [u8]) -> usize + Send + Sync + 'static>;

/// A custom CTAP command with its handler
///
/// Custom commands allow extending the CTAP2 protocol with vendor-specific
/// functionality. The command byte must not conflict with standard CTAP2
/// commands (0x01-0x0b).
///
/// # Example
///
/// ```no_run
/// use keylib::CustomCommand;
/// use std::sync::Arc;
///
/// let cmd = CustomCommand::new(0x41, Arc::new(|auth, request, response| {
///     // Handle custom command 0x41
///     // Parse request CBOR, perform operation, write CBOR response
///     response[0] = 0x00; // CTAP2_OK
///     1 // Response length
/// }));
/// ```
#[derive(Clone)]
pub struct CustomCommand {
    /// Command byte (e.g., 0x41 for vendor-specific commands)
    pub cmd: u8,
    /// Handler function for this command
    pub handler: CustomCommandHandler,
}

impl CustomCommand {
    /// Create a new custom command
    ///
    /// # Arguments
    ///
    /// * `cmd` - Command byte (must not conflict with standard CTAP2 commands 0x01-0x0b)
    /// * `handler` - Function to handle requests for this command
    ///
    /// # Example
    ///
    /// ```no_run
    /// use keylib::CustomCommand;
    /// use std::sync::Arc;
    ///
    /// let handler = Arc::new(|_auth, request: &[u8], response: &mut [u8]| {
    ///     // Your custom command logic here
    ///     response[0] = 0x00; // CTAP2_OK
    ///     1
    /// });
    ///
    /// let cmd = CustomCommand::new(0x41, handler);
    /// ```
    pub fn new(cmd: u8, handler: CustomCommandHandler) -> Self {
        Self { cmd, handler }
    }
}

impl std::fmt::Debug for CustomCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomCommand")
            .field("cmd", &format!("0x{:02x}", self.cmd))
            .field("handler", &"<function>")
            .finish()
    }
}
