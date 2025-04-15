use std::{collections::HashMap, ffi::c_void, sync::RwLock};

use libloading::Library;
use once_cell::sync::Lazy;

use crate::error::{NscqError, Result};

/// Function pointer type
type FunctionPointer = ;

/// Function cache type
type FunctionCache = RwLock<HashMap<String, FunctionPointer>>;

/// State for the NSCQ library
struct NscqLibState {
    /// The loaded library
    library: Library,
    /// The cache of function pointers
    cache: FunctionCache,
}

/// Global static variable, lazily initialized using `once_cell::sync::Lazy`.
/// Holds the result of loading the library and initializing the cache.
static NSCQ_STATE: Lazy<Result<NscqLibState>> = Lazy::new(|| {
    // Only supported on Linux
    if !cfg!(target_os = "linux") {
        return Err(NscqError::UnsupportedPlatform);
    }

    let lib_name = "libnvidia-nscq.so";

    // Attempt to load the shared library.
    // Safety: Loading external C libraries and interacting with their functions
    // is inherently unsafe. We assume the library exists, is compatible, and
    // its functions adhere to the expected C ABI.
    match unsafe { Library::new(lib_name) } {
        Ok(library) => Ok(NscqLibState {
            library,
            // Initialize an empty cache protected by a Mutex
            cache: RwLock::new(HashMap::new()),
        }),
        Err(e) => Err(NscqError::LibraryLoadError(e)),
    }
});

/// Finds a function symbol in the loaded `nvidia-nscq` library, using a cache.
///
/// Takes the function name as a null-terminated C string (`*const c_char`).
/// Returns a raw pointer (`*const c_void`) to the function.
///
/// # Safety
///
/// - The caller must ensure `name_ptr` points to a valid, null-terminated C string.
/// - The returned pointer must be transmuted to the correct function signature
///   before being called. Misuse can lead to undefined behavior.
/// - The pointer is valid only as long as the `NSCQ_STATE` static variable lives
///   (effectively, the lifetime of the program, thanks to `Lazy`).
///
/// # Errors
///
/// Returns an error string if the library failed to load initially, or if the
/// specified symbol cannot be found in the library.
pub unsafe fn nscq_find_func(name_ptr: *const c_char) -> Result<*const c_void, String> {
    // Ensure the C string pointer is valid
    if name_ptr.is_null() {
        return Err("Function name pointer cannot be null".to_string());
    }
    // Safely create a byte slice from the C string
    let name_cstr = CStr::from_ptr(name_ptr);
    let name_bytes = name_cstr.to_bytes(); // Does not include null terminator

    // Access the global library state (or initialize it on first access)
    // If initialization failed, propagate the error.
    let state = NSCQ_STATE.as_ref().map_err(|e| e.clone())?;

    // Lock the cache for reading/writing. Panic on poisoning.
    let mut cache = state.cache.lock().expect("NSCQ function cache mutex poisoned");

    // Check if the function pointer is already in the cache
    if let Some(&ptr) = cache.get(name_bytes) {
        return Ok(ptr);
    }

    // Function not in cache, load symbol from the library
    // We must provide a type signature to `library.get()`. Since we don't know
    // the specific signature here, we use a generic function type like
    // `unsafe extern "C" fn()`. The actual signature correctness is deferred
    // to the caller via unsafe transmutation.
    // Note: We pass `name_bytes` (without null) because `libloading` expects this.
    let symbol: Symbol<unsafe extern "C" fn()> = state
        .library
        .get(name_bytes)
        .map_err(|e| format!("Failed to find symbol '{}': {}", name_cstr.to_string_lossy(), e))?;

    // Get the raw pointer from the symbol.
    // `into_raw` prevents the symbol from being dropped when `symbol` goes out
    // of scope, transferring ownership implicitly to the `Library` managed
    // by the `Lazy` static.
    let raw_ptr = symbol.into_raw() as *const c_void;

    // Store the raw pointer in the cache.
    // We use `name_bytes.to_vec()` to store an owned copy of the name.
    cache.insert(name_bytes.to_vec(), raw_ptr);

    Ok(raw_ptr)
}