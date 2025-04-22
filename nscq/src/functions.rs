use std::ffi::c_void;

use super::types::{
    NscqCallback, NscqLabel, NscqObserver, NscqRc, NscqSession, NscqUuid, UserData,
};

/// Error codes for NSCQ operations.
#[must_use]
pub const fn nscq_error_to_str(rc: NscqRc) -> &'static str {
    match rc {
        0 => "NSCQ_RC_SUCCESS",
        1 => "NSCQ_RC_WARNING_RDT_INIT_FAILURE",
        -1 => "NSCQ_RC_ERROR_NOT_IMPLEMENTED",
        -2 => "NSCQ_RC_ERROR_INVALID_UUID",
        -3 => "NSCQ_RC_ERROR_RESOURCE_NOT_MOUNTABLE",
        -4 => "NSCQ_RC_ERROR_OVERFLOW",
        -5 => "NSCQ_RC_ERROR_UNEXPECTED_VALUE",
        -6 => "NSCQ_RC_ERROR_UNSUPPORTED_DRV",
        -7 => "NSCQ_RC_ERROR_DRV",
        -8 => "NSCQ_RC_ERROR_TIMEOUT",
        -127 => "NSCQ_RC_ERROR_EXT",
        -128 => "NSCQ_RC_ERROR_UNSPECIFIED",
        _ => "Unknown error code",
    }
}

/// Creates a new session with flags.
///
/// # Arguments
///
/// * `flags` - Flags for the session creation.
///
/// # Returns
///
/// * `Ok(NscqSession)` if successful, or an error code if it fails.
pub fn nscq_session_create(flags: u32) -> Result<NscqSession, NscqRc> {
    let session_result = unsafe { super::bindings::NSCQ_SESSION_CREATE(flags) };
    if session_result.rc != 0 {
        return Err(session_result.rc);
    }
    Ok(session_result.session)
}

/// Destroys the session.
///
/// # Arguments
///
/// * `session` - The session to destroy
pub fn nscq_session_destroy(session: NscqSession) {
    unsafe { super::bindings::NSCQ_SESSION_DESTROY(session) }
}

/// Mounts a UUID to the session.
///
/// # Arguments
///
/// * `session` - The session to mount the UUID to.
/// * `uuid` - The UUID to mount.
/// * `flags` - Flags for the mount operation.
///
/// # Returns
///
/// * `Ok(())` if successful, or an error code if it fails.
pub fn nscq_session_mount(session: NscqSession, uuid: NscqUuid, flags: u32) -> Result<(), NscqRc> {
    let result = unsafe { super::bindings::NSCQ_SESSION_MOUNT(session, uuid, flags) };
    if result != 0 {
        return Err(result);
    }
    Ok(())
}

/// Unmounts a UUID from the session.
///
/// # Arguments
///
/// * `session` - The session to unmount the UUID from.
/// * `uuid` - The UUID to unmount.
///
/// # Returns
///
/// * `Ok(())` if successful, or an error code if it fails.
pub fn nscq_session_unmount(session: NscqSession, uuid: NscqUuid) -> Result<(), NscqRc> {
    let result = unsafe { super::bindings::NSCQ_SESSION_UNMOUNT(session, uuid) };
    if result != 0 {
        Err(result)
    } else {
        Ok(())
    }
}

/// Converts a UUID to a label.
///
/// # Arguments
///
/// * `uuid` - The UUID to convert.
/// * `flags` - Flags for the conversion operation.
///
/// # Returns
///
/// * `Ok(NscqLabel)` if successful, or an error code if it fails.
pub fn nscq_uuid_to_label(uuid: NscqUuid, flags: u32) -> Result<NscqLabel, NscqRc> {
    let label = NscqLabel::new();
    let res = unsafe { super::bindings::NSCQ_UUID_TO_LABEL(uuid, &label, flags) };
    if res != 0 {
        Err(res)
    } else {
        Ok(label)
    }
}

/// Observes a path in the session.
///
/// # Arguments
///
/// * `session` - The session to observe.
/// * `path` - The path to observe.
/// * `callback` - The callback function to call.
/// * `user_data` - User data to pass to the callback.
/// * `flags` - Flags for the observation.
///
/// # Returns
///
/// * `Ok(())` if successful, or an error code if it fails.
pub fn nscq_session_path_observe(
    session: NscqSession,
    path: &str,
    callback: &NscqCallback,
    user_data: UserData,
    flags: u32,
) -> Result<(), NscqRc> {
    let c_path = std::ffi::CString::new(path).map_err(|_| -5)?;
    let res = unsafe {
        super::bindings::NSCQ_SESSION_PATH_OBSERVE(
            session,
            c_path.as_ptr(),
            callback.as_ptr(),
            user_data,
            flags,
        )
    };
    if res != 0 {
        Err(res)
    } else {
        Ok(())
    }
}

/// Registers an observer for a path in the session.
///
/// # Arguments
///
/// * `session` - The session to register the observer for.
/// * `path` - The path to register the observer for.
/// * `callback` - The callback function to call.
/// * `user_data` - User data to pass to the callback.
/// * `flags` - Flags for the registration.
///
/// # Returns
///
/// * `Ok(NscqObserver)` if successful, or an error code if it fails.
pub fn nscq_session_path_register_observer(
    session: NscqSession,
    path: &str,
    callback: &NscqCallback,
    user_data: UserData,
    flags: u32,
) -> Result<NscqObserver, NscqRc> {
    let c_path = std::ffi::CString::new(path).map_err(|_| -5)?;
    let res = unsafe {
        super::bindings::NSCQ_SESSION_PATH_REGISTER_OBSERVER(
            session,
            c_path.as_ptr(),
            callback.as_ptr(),
            user_data,
            flags,
        )
    };
    if res.rc != 0 {
        Err(res.rc)
    } else {
        Ok(res.observer)
    }
}

/// Deregisters an observer.
///
/// # Arguments
///
/// * `observer` - The observer to deregister.
#[allow(dead_code)]
pub fn nscq_observer_deregister(observer: NscqObserver) {
    unsafe { super::bindings::NSCQ_OBSERVER_DEREGISTER(observer) }
}

/// Observes a session.
///
/// # Arguments
///
/// * `observer` - The observer to observe.
/// * `flags` - Flags for the observation.
///
/// # Returns
///
/// * `Ok(())` if successful, or an error code if it fails.
#[allow(dead_code)]
pub fn nscq_observer_observe(observer: NscqObserver, flags: u32) -> Result<(), NscqRc> {
    let res = unsafe { super::bindings::NSCQ_OBSERVER_OBSERVE(observer, flags) };
    if res != 0 {
        Err(res)
    } else {
        Ok(())
    }
}

/// Observes a session.
///
/// # Arguments
///
/// * `session` - The session to observe.
/// * `flags` - Flags for the observation.
///
/// # Returns
///
/// * `Ok(())` if successful, or an error code if it fails.
pub fn nscq_session_observe(session: NscqSession, flags: u32) -> Result<(), NscqRc> {
    let res = unsafe { super::bindings::NSCQ_SESSION_OBSERVE(session, flags) };
    if res != 0 {
        Err(res)
    } else {
        Ok(())
    }
}

/// Sets the input for a session.
///
/// # Arguments
///
/// * `session` - The session to set the input for.
/// * `input_arg` - The input argument.
/// * `input_size` - The size of the input argument.
/// * `flags` - Flags for the input operation.
///
/// # Returns
///
/// * `Ok(())` if successful, or an error code if it fails.
pub fn nscq_session_set_input(
    session: NscqSession,
    input_arg: *const c_void,
    input_size: u32,
    flags: u32,
) -> Result<(), NscqRc> {
    let res =
        unsafe { super::bindings::NSCQ_SESSION_SET_INPUT(session, flags, input_arg, input_size) };
    if res != 0 {
        Err(res)
    } else {
        Ok(())
    }
}
