use core::{ffi::c_void, ptr::null_mut};

use wdk::{nt_success, println};
use wdk_sys::{
    CLIENT_ID, NTSTATUS, OBJ_KERNEL_HANDLE, OBJECT_ATTRIBUTES, PROCESS_ALL_ACCESS,
    ntddk::{KeGetCurrentIrql, ZwOpenProcess, ZwTerminateProcess},
};

use crate::ffi::InitializeObjectAttributes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverMode {
    ReportOnly,
    Blocking,
}

pub static DRIVER_MODE: DriverMode = DriverMode::Blocking;

pub struct Containment {}

impl Containment {
    pub fn contain_process(pid: u32) {
        println!("[sanctum] [*] Containing process: {pid}");
        // todo actual containment

        let _ = terminate_process(pid);
    }
}

fn terminate_process(pid: u32) -> NTSTATUS {
    let mut handle: *mut c_void = null_mut();
    let mut oa = OBJECT_ATTRIBUTES::default();
    let _ = unsafe {
        InitializeObjectAttributes(
            &mut oa,
            null_mut(),
            OBJ_KERNEL_HANDLE,
            null_mut(),
            null_mut(),
        )
    };

    let mut client_id = CLIENT_ID {
        UniqueProcess: pid as *mut c_void,
        UniqueThread: null_mut(),
    };

    let irql = unsafe { KeGetCurrentIrql() };
    println!("About to open process? IRQL: {irql}");

    let status = unsafe { ZwOpenProcess(&mut handle, PROCESS_ALL_ACCESS, &mut oa, &mut client_id) };

    if !nt_success(status) {
        println!("[sanctum] [-] Failed to suspend process, pid: {pid}. Error: {status:#X}");
        return status;
    }

    let status = unsafe { ZwTerminateProcess(handle, 1) };

    if !nt_success(status) {
        println!("[sanctum] [-] Error terminating process.")
    }

    status
}
