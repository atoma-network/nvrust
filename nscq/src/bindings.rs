use super::types::{
    NscqLabel, NscqObserver, NscqObserverResult, NscqRc, NscqSession, NscqSessionResult, NscqUuid,
    UserData,
};
use lazy_static::lazy_static;
use libloading::{Library, Symbol};
use std::ffi::c_void;

/// Function to find a library in the system's library path.
///
/// This function searches for the specified library name in the `LD_LIBRARY_PATH` environment variable.
/// It constructs the full path to the library by appending `lib` and `.so` to the name.
/// If the library is found, it returns the full path as a `String`.
/// If the library is not found, it returns `None`.
///
/// # Arguments
///
/// * `name` - The name of the library to search for (without `lib` prefix and `.so` suffix).
///
/// # Returns
///
/// * `Option<String>` - The full path to the library if found, otherwise `None`.
fn find_library(name: &str) -> Option<String> {
    let paths = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
    for path in paths.split(':') {
        let lib_path = format!("{}/lib{}.so", path, name);
        if std::path::Path::new(&lib_path).exists() {
            return Some(lib_path);
        }
    }
    None
}

lazy_static! {
    static ref lib: Library = unsafe {
        Library::new(find_library("nvidia-nscq").expect("Failed to find nvidia-nscq library"))
            .expect("Failed to load nvidia-nscq library")
    };
    pub static ref nscq_session_create: Symbol<'static, unsafe extern "C" fn(u32) -> NscqSessionResult> = unsafe {
        lib.get(b"nscq_session_create")
            .expect("Failed to load nscq_session_create function")
    };
    pub static ref nscq_session_destroy: Symbol<'static, unsafe extern "C" fn(NscqSession)> = unsafe {
        lib.get(b"nscq_session_destroy")
            .expect("Failed to load nscq_session_destroy function")
    };
    pub static ref nscq_session_mount: Symbol<'static, unsafe extern "C" fn(NscqSession, NscqUuid, u32) -> NscqRc> = unsafe {
        lib.get(b"nscq_session_mount")
            .expect("Failed to load nscq_session_mount function")
    };
    pub static ref nscq_session_unmount: Symbol<'static, unsafe extern "C" fn(NscqSession, NscqUuid) -> NscqRc> = unsafe {
        lib.get(b"nscq_session_unmount")
            .expect("Failed to load nscq_session_unmount function")
    };
    pub static ref nscq_uuid_to_label: Symbol<'static, unsafe extern "C" fn(NscqUuid, &NscqLabel, u32) -> NscqRc> = unsafe {
        lib.get(b"nscq_uuid_to_label")
            .expect("Failed to load nscq_uuid_to_label function")
    };
    pub static ref nscq_session_path_observe: Symbol<
        'static,
        unsafe extern "C" fn(NscqSession, *const i8, *const c_void, UserData, u32) -> NscqRc,
    > = unsafe {
        lib.get(b"nscq_session_path_observe")
            .expect("Failed to load nscq_session_path_observe function")
    };
    pub static ref nscq_session_path_register_observer: Symbol<
        'static,
        unsafe extern "C" fn(
            NscqSession,
            *const i8,
            *const c_void,
            UserData,
            u32,
        ) -> NscqObserverResult,
    > = unsafe {
        lib.get(b"nscq_session_path_register_observer")
            .expect("Failed to load nscq_session_path_register_observer function")
    };
    pub static ref nscq_observer_deregister: Symbol<'static, unsafe extern "C" fn(NscqObserver)> = unsafe {
        lib.get(b"nscq_observer_deregister")
            .expect("Failed to load nscq_observer_deregister function")
    };
    pub static ref nscq_observer_observe: Symbol<'static, unsafe extern "C" fn(NscqObserver, u32) -> NscqRc> = unsafe {
        lib.get(b"nscq_observer_observe")
            .expect("Failed to load nscq_observer_observe function")
    };
    pub static ref nscq_session_observe: Symbol<'static, unsafe extern "C" fn(NscqSession, u32) -> NscqRc> = unsafe {
        lib.get(b"nscq_session_observe")
            .expect("Failed to load nscq_session_observe function")
    };
    pub static ref nscq_session_set_input: Symbol<'static, unsafe extern "C" fn(NscqSession, u32, &mut c_void, u32) -> NscqRc> = unsafe {
        lib.get(b"nscq_session_set_input")
            .expect("Failed to load nscq_session_set_input function")
    };
}
