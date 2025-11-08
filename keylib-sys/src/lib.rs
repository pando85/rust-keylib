#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod raw {
    // include the generated bindings from OUT_DIR at compile time
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// statically link hidapi
#[allow(unused_imports, clippy::single_component_path_imports)]
use hidapi;
