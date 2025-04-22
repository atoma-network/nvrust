use std::ffi::c_void;

use crate::functions::nscq_session_destroy;

use super::{
    functions::{
        nscq_session_create, nscq_session_mount, nscq_session_observe, nscq_session_path_observe,
        nscq_session_path_register_observer, nscq_session_set_input, nscq_session_unmount,
    },
    types::{NscqCallback, NscqObserver, NscqRc, NscqSession, NscqUuid, UserData},
};

/// A session object that represents a connection to the NSCQ service.
pub struct Session {
    session: NscqSession,
}

impl Session {
    /// Creates a new session with the specified flags and mounts the given UUIDs.
    ///
    /// # Arguments
    ///
    /// * `flags` - Flags for the session.
    /// * `uuids` - A vector of UUIDs to mount.
    ///
    /// # Returns
    ///
    /// * `Ok(Session)` if successful, or an error code if it fails.
    pub fn new(flags: u32, uuids: Vec<NscqUuid>) -> Result<Self, NscqRc> {
        let session = nscq_session_create(flags)?;
        for uuid in uuids {
            nscq_session_mount(session, uuid, flags)?;
        }
        Ok(Self { session })
    }

    /// Mounts a UUID to the session.
    ///
    /// # Arguments
    ///
    /// * `uuid` - The UUID to mount.
    /// * `flags` - Flags for the mount operation.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if successful, or an error code if it fails.
    #[allow(dead_code)]
    pub fn mount(&self, uuid: NscqUuid, flags: u32) -> Result<(), NscqRc> {
        nscq_session_mount(self.session, uuid, flags)
    }

    /// Unmounts a UUID from the session.
    ///
    /// # Arguments
    ///
    /// * `uuid` - The UUID to unmount.
    #[allow(dead_code)]
    pub fn unmount(&self, uuid: NscqUuid) -> Result<(), NscqRc> {
        nscq_session_unmount(self.session, uuid)
    }

    /// Observes a path with the specified callback and user data.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to observe.
    /// * `callback` - The callback function to call.
    /// * `user_data` - User data to pass to the callback.
    /// * `flags` - Flags for the observation.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if successful, or an error code if it fails.
    pub fn path_observe(
        &self,
        path: &str,
        callback: &NscqCallback,
        user_data: UserData,
        flags: u32,
    ) -> Result<(), NscqRc> {
        nscq_session_path_observe(self.session, path, callback, user_data, flags)
    }

    /// Registers an observer for a path with the specified callback and user data.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to observe.
    /// * `callback` - The callback function to call.
    /// * `user_data` - User data to pass to the callback.
    /// * `flags` - Flags for the observation.
    ///
    /// # Returns
    ///
    /// * `Ok(NscqObserver)` if successful, or an error code if it fails.
    #[allow(dead_code)]
    pub fn path_register_observer(
        &self,
        path: &str,
        callback: &NscqCallback,
        user_data: UserData,
        flags: u32,
    ) -> Result<NscqObserver, NscqRc> {
        nscq_session_path_register_observer(self.session, path, callback, user_data, flags)
    }

    /// Observes the session with the specified flags.
    ///
    /// # Arguments
    ///
    /// * `flags` - Flags for the observation.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if successful, or an error code if it fails.
    #[allow(dead_code)]
    pub fn observe(&self, flags: u32) -> Result<(), NscqRc> {
        nscq_session_observe(self.session, flags)
    }

    /// Sets the input for the session with the specified arguments and flags.
    ///
    /// # Arguments
    ///
    /// * `input_arg` - The input argument to set.
    /// * `input_size` - The size of the input argument.
    /// * `flags` - Flags for the input operation.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if successful, or an error code if it fails.
    pub fn set_input(
        &self,
        input_arg: &mut c_void,
        input_size: u32,
        flags: u32,
    ) -> Result<(), NscqRc> {
        nscq_session_set_input(self.session, input_arg, input_size, flags)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        nscq_session_destroy(self.session);
    }
}
