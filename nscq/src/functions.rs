use std::ffi::{c_uint, c_void};

use super::types::{
    NscqCallback, NscqLabel, NscqObserver, NscqRc, NscqSession, NscqUuid, UserData,
};

fn error_to_str(rc: NscqRc) -> &'static str {
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

fn nsqc_handle_rc(rc: NscqRc) {
    if rc < 0 {
        panic!("NSCQ error: {}", error_to_str(rc));
    }
    if rc > 0 {
        println!("NSCQ warning: {}", error_to_str(rc));
    }
}

pub fn nscq_session_create(flags: c_uint) -> NscqSession {
    let session_result = unsafe { super::bindings::nscq_session_create(flags) };
    nsqc_handle_rc(session_result.rc);
    session_result.session
}

pub fn nscq_session_destroy(session: NscqSession) {
    unsafe { super::bindings::nscq_session_destroy(session) }
}

pub fn nscq_session_mount(session: NscqSession, uuid: NscqUuid, flags: c_uint) -> NscqRc {
    let result = unsafe { super::bindings::nscq_session_mount(session, uuid, flags) };
    nsqc_handle_rc(result);
    result
}

pub fn nscq_session_unmount(session: NscqSession, uuid: NscqUuid) -> NscqRc {
    let result = unsafe { super::bindings::nscq_session_unmount(session, uuid) };
    nsqc_handle_rc(result);
    result
}

pub fn nscq_uuid_to_label(uuid: NscqUuid, flags: c_uint) -> NscqLabel {
    let label = NscqLabel::new();
    unsafe {
        let res = super::bindings::nscq_uuid_to_label(uuid, &label, flags);
        if res != 0 {
            panic!("Failed to get label for UUID: {}", res);
        }
    }
    label
}

pub fn nscq_session_path_observe(
    session: NscqSession,
    path: &str,
    callback: NscqCallback,
    user_data: UserData,
    flags: c_uint,
) -> NscqRc {
    let c_path = std::ffi::CString::new(path).unwrap();
    let res = unsafe {
        super::bindings::nscq_session_path_observe(
            session,
            c_path.as_ptr(),
            callback.as_ptr(),
            user_data,
            flags,
        )
    };
    nsqc_handle_rc(res);
    res
}

pub fn nscq_session_path_register_observer(
    session: NscqSession,
    path: &str,
    callback: NscqCallback,
    user_data: UserData,
    flags: c_uint,
) -> NscqObserver {
    let c_path = std::ffi::CString::new(path).unwrap();
    let res = unsafe {
        super::bindings::nscq_session_path_register_observer(
            session,
            c_path.as_ptr(),
            callback.as_ptr(),
            user_data,
            flags,
        )
    };
    nsqc_handle_rc(res.rc);
    res.observer
}

pub fn nscq_observer_deregister(observer: NscqObserver) {
    unsafe { super::bindings::nscq_observer_deregister(observer) }
}

pub fn nscq_observer_observe(observer: NscqObserver, flags: c_uint) -> NscqRc {
    let res = unsafe { super::bindings::nscq_observer_observe(observer, flags) };
    nsqc_handle_rc(res);
    res
}

pub fn nscq_session_observe(session: NscqSession, flags: c_uint) -> NscqRc {
    let res = unsafe { super::bindings::nscq_session_observe(session, flags) };
    nsqc_handle_rc(res);
    res
}

pub fn nscq_session_set_input(
    session: NscqSession,
    input_arg: &mut c_void,
    input_size: c_uint,
    flags: c_uint,
) -> NscqRc {
    let res =
        unsafe { super::bindings::nscq_session_set_input(session, flags, input_arg, input_size) };
    nsqc_handle_rc(res);
    res
}
