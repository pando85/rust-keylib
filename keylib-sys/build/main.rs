#[cfg(feature = "bundled")]
mod bundled;
mod source;

use std::env;

fn main() {
    // Check if bundled feature is enabled
    let use_bundled = env::var("CARGO_FEATURE_BUNDLED").is_ok();

    if use_bundled {
        #[cfg(feature = "bundled")]
        bundled::build();

        #[cfg(not(feature = "bundled"))]
        panic!("bundled feature enabled but bundled support not compiled in");
    } else {
        source::build();
    }
}
