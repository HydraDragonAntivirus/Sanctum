//! This module handles callback implementations and and other function related to processes.

use core::{
    arch::asm,
    ffi::c_void,
    ptr::null_mut,
};

use wdk::println;
use wdk_sys::{
    BOOLEAN,
    ntddk::PsSetCreateThreadNotifyRoutine,
};

use crate::{
    alt_syscalls::{AltSyscallStatus, AltSyscalls},
    utils::thread_to_process_name,
};

/// Instructs the driver to register the thread creation callback routine.
pub fn set_thread_creation_callback() {
    if unsafe { PsSetCreateThreadNotifyRoutine(Some(thread_callback)) } != 0 {
        println!("Failed to call set_thread_creation_callback");
    }
}

/// The callback routine that specifically deals with thread creation monitoring. This function is used to handle:
///
/// - Newly created threads which need analysis for signs of malicious behaviour
/// - Setting up the AltSyscallHandler so that we can intercept syscalls kernel-side from usermode.
///
/// # Args
/// - pid: The process ID of the process.
/// - thread_id: The thread ID of the thread.
/// = create: Indicates whether the thread was created (TRUE) or deleted (FALSE).
pub unsafe extern "C" fn thread_callback(
    pid: *mut c_void,
    thread_id: *mut c_void,
    create: BOOLEAN,
) {
    let pid = pid as u32;
    let thread_id = thread_id as u32;

    thread_reg_alt_callbacks();
}

pub fn thread_reg_alt_callbacks() {
    let mut ke_thread: *mut c_void = null_mut();

    unsafe {
        asm!(
            "mov {}, gs:[0x188]",
            out(reg) ke_thread,
        )
    };

    let thread_process_name = match thread_to_process_name(ke_thread as *mut _) {
        Ok(t) => t.to_lowercase(),
        Err(e) => {
            println!("[sanctum] [-] Could not get process name on new thread creation. {:?}", e);
            return;
        },
    };

    AltSyscalls::configure_thread_for_alt_syscalls(ke_thread as *mut _, AltSyscallStatus::Enable);
    AltSyscalls::configure_process_for_alt_syscalls(ke_thread as *mut _);
}
