use super::types::{
    NscqLabel, NscqObserver, NscqObserverResult, NscqRc, NscqSession, NscqSessionResult, NscqUuid,
    UserData,
};
use libloading::{Library, Symbol};
use std::{ffi::c_void, sync::LazyLock};

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
        let lib_path = format!("{path}/lib{name}.so");
        if std::path::Path::new(&lib_path).exists() {
            return Some(lib_path);
        }
    }
    None
}

/// Lazy static library for the `nvidia-nscq` library.
static LIB: LazyLock<Library> = LazyLock::new(|| unsafe {
    Library::new(find_library("nvidia-nscq").expect("Failed to find nvidia-nscq library"))
        .expect("Failed to load nvidia-nscq library")
});

/// Lazy static symbol for the `nscq_session_create` function.
pub static NSCQ_SESSION_CREATE: LazyLock<
    Symbol<'static, unsafe extern "C" fn(u32) -> NscqSessionResult>,
> = LazyLock::new(|| unsafe {
    LIB.get(b"nscq_session_create")
        .expect("Failed to load nscq_session_create function")
});

/// Lazy static symbol for the `nscq_session_destroy` function.
pub static NSCQ_SESSION_DESTROY: LazyLock<Symbol<'static, unsafe extern "C" fn(NscqSession)>> =
    LazyLock::new(|| unsafe {
        LIB.get(b"nscq_session_destroy")
            .expect("Failed to load nscq_session_destroy function")
    });

/// Lazy static symbol for the `nscq_session_mount` function.
pub static NSCQ_SESSION_MOUNT: LazyLock<
    Symbol<'static, unsafe extern "C" fn(NscqSession, NscqUuid, u32) -> NscqRc>,
> = LazyLock::new(|| unsafe {
    LIB.get(b"nscq_session_mount")
        .expect("Failed to load nscq_session_mount function")
});

/// Lazy static symbol for the `nscq_session_unmount` function.
pub static NSCQ_SESSION_UNMOUNT: LazyLock<
    Symbol<'static, unsafe extern "C" fn(NscqSession, NscqUuid) -> NscqRc>,
> = LazyLock::new(|| unsafe {
    LIB.get(b"nscq_session_unmount")
        .expect("Failed to load nscq_session_unmount function")
});

/// Lazy static symbol for the `nscq_uuid_to_label` function.
pub static NSCQ_UUID_TO_LABEL: LazyLock<
    Symbol<'static, unsafe extern "C" fn(NscqUuid, &NscqLabel, u32) -> NscqRc>,
> = LazyLock::new(|| unsafe {
    LIB.get(b"nscq_uuid_to_label")
        .expect("Failed to load nscq_uuid_to_label function")
});

/// Lazy static symbol for the `nscq_session_path_observe` function.
pub static NSCQ_SESSION_PATH_OBSERVE: LazyLock<
    Symbol<
        'static,
        unsafe extern "C" fn(NscqSession, *const i8, *const c_void, UserData, u32) -> NscqRc,
    >,
> = LazyLock::new(|| unsafe {
    LIB.get(b"nscq_session_path_observe")
        .expect("Failed to load nscq_session_path_observe function")
});

/// Lazy static symbol for the `nscq_session_path_register_observer` function.
pub static NSCQ_SESSION_PATH_REGISTER_OBSERVER: LazyLock<
    Symbol<
        'static,
        unsafe extern "C" fn(
            NscqSession,
            *const i8,
            *const c_void,
            UserData,
            u32,
        ) -> NscqObserverResult,
    >,
> = LazyLock::new(|| unsafe {
    LIB.get(b"nscq_session_path_register_observer")
        .expect("Failed to load nscq_session_path_register_observer function")
});

/// Lazy static symbol for the `nscq_observer_deregister` function.
pub static NSCQ_OBSERVER_DEREGISTER: LazyLock<Symbol<'static, unsafe extern "C" fn(NscqObserver)>> =
    LazyLock::new(|| unsafe {
        LIB.get(b"nscq_observer_deregister")
            .expect("Failed to load nscq_observer_deregister function")
    });

/// Lazy static symbol for the `nscq_observer_observe` function.
pub static NSCQ_OBSERVER_OBSERVE: LazyLock<
    Symbol<'static, unsafe extern "C" fn(NscqObserver, u32) -> NscqRc>,
> = LazyLock::new(|| unsafe {
    LIB.get(b"nscq_observer_observe")
        .expect("Failed to load nscq_observer_observe function")
});

/// Lazy static symbol for the `nscq_session_observe` function.
pub static NSCQ_SESSION_OBSERVE: LazyLock<
    Symbol<'static, unsafe extern "C" fn(NscqSession, u32) -> NscqRc>,
> = LazyLock::new(|| unsafe {
    LIB.get(b"nscq_session_observe")
        .expect("Failed to load nscq_session_observe function")
});

/// Lazy static symbol for the `nscq_session_set_input` function.
pub static NSCQ_SESSION_SET_INPUT: LazyLock<
    Symbol<'static, unsafe extern "C" fn(NscqSession, u32, *const c_void, u32) -> NscqRc>,
> = LazyLock::new(|| unsafe {
    LIB.get(b"nscq_session_set_input")
        .expect("Failed to load nscq_session_set_input function")
});
