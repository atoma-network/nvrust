use std::ffi::c_void;

use crate::functions::nscq_session_destroy;

use super::{
    functions::{
        nscq_session_create, nscq_session_mount, nscq_session_observe, nscq_session_path_observe,
        nscq_session_path_register_observer, nscq_session_set_input, nscq_session_unmount,
    },
    types::{NscqCallback, NscqObserver, NscqRc, NscqSession, NscqUuid, UserData},
};

pub struct Session {
    session: NscqSession,
}

impl Session {
    pub fn new(flags: u32, uuids: Vec<NscqUuid>) -> Self {
        let session = nscq_session_create(flags);
        for uuid in uuids {
            nscq_session_mount(session, uuid, flags);
        }
        Session { session }
    }

    pub fn mount(&self, uuid: NscqUuid, flags: u32) -> NscqRc {
        nscq_session_mount(self.session, uuid, flags)
    }

    pub fn unmount(&self, uuid: NscqUuid) {
        nscq_session_unmount(self.session, uuid);
    }

    pub fn path_observe(
        &self,
        path: &str,
        callback: NscqCallback,
        user_data: UserData,
        flags: u32,
    ) -> NscqRc {
        nscq_session_path_observe(self.session, path, callback, user_data, flags)
    }

    pub fn path_register_observer(
        &self,
        path: &str,
        callback: NscqCallback,
        user_data: UserData,
        flags: u32,
    ) -> NscqObserver {
        nscq_session_path_register_observer(self.session, path, callback, user_data, flags)
    }

    pub fn observe(&self, flags: u32) -> NscqRc {
        nscq_session_observe(self.session, flags)
    }

    pub fn set_input(&self, input_arg: &mut c_void, input_size: u32, flags: u32) -> NscqRc {
        nscq_session_set_input(self.session, input_arg, input_size, flags)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        nscq_session_destroy(self.session);
    }
}
