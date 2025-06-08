// FFI for functions not yet implemented in the Rust Windows Driver project

use core::{ffi::c_void, ptr::null_mut};

use wdk_sys::{
    ntddk::{KeGetCurrentIrql, KeInitializeEvent}, ACCESS_MASK, DISPATCH_LEVEL, FALSE, FAST_MUTEX, FM_LOCK_BIT, HANDLE, HANDLE_PTR, NTSTATUS, OBJECT_ATTRIBUTES, PDRIVER_OBJECT, PHANDLE, PIO_STACK_LOCATION, PIRP, POBJECT_ATTRIBUTES, PROCESSINFOCLASS, PSECURITY_DESCRIPTOR, PULONG, PUNICODE_STRING, ULONG, _EVENT_TYPE::SynchronizationEvent
};

pub unsafe fn IoGetCurrentIrpStackLocation(irp: PIRP) -> PIO_STACK_LOCATION {
    assert!((*irp).CurrentLocation <= (*irp).StackCount + 1); // todo maybe do error handling instead of an assert?
    (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation
}

#[allow(non_snake_case)]
pub unsafe fn ExInitializeFastMutex(kmutex: *mut FAST_MUTEX) {
    // check IRQL
    let irql = unsafe { KeGetCurrentIrql() };
    assert!(irql as u32 <= DISPATCH_LEVEL);

    core::ptr::write_volatile(&mut (*kmutex).Count, FM_LOCK_BIT as i32);

    (*kmutex).Owner = core::ptr::null_mut();
    (*kmutex).Contention = 0;
    KeInitializeEvent(&mut (*kmutex).Event, SynchronizationEvent, FALSE as _)
}

/// The InitializeObjectAttributes macro initializes the opaque OBJECT_ATTRIBUTES structure,
/// which specifies the properties of an object handle to routines that open handles.
///
/// # Returns
/// This function will return an Err if the POBJECT_ATTRIBUTES is null. Otherwise, it will return
/// Ok(())
#[allow(non_snake_case)]
pub unsafe fn InitializeObjectAttributes(
    p: POBJECT_ATTRIBUTES,
    n: PUNICODE_STRING,
    a: ULONG,
    r: HANDLE,
    s: PSECURITY_DESCRIPTOR,
) -> Result<(), ()> {
    // check the validity of the OBJECT_ATTRIBUTES pointer
    if p.is_null() {
        return Err(());
    }

    (*p).Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    (*p).RootDirectory = r;
    (*p).Attributes = a;
    (*p).ObjectName = n;
    (*p).SecurityDescriptor = s;
    (*p).SecurityQualityOfService = null_mut();

    Ok(())
}

unsafe extern "system" {
    pub unsafe fn PsGetProcessImageFileName(p_eprocess: *const c_void) -> *const c_void;
    pub unsafe fn NtQueryInformationProcess(
        handle: HANDLE,
        flags: i32,
        process_information: *mut c_void,
        len: ULONG,
        return_len: PULONG,
    ) -> NTSTATUS;
}

unsafe extern "system" {
    pub unsafe fn ZwGetNextProcess(
        handle: HANDLE,
        access: ACCESS_MASK,
        attr: ULONG,
        flags: ULONG,
        new_proc_handle: PHANDLE,
    ) -> NTSTATUS;

    pub unsafe fn ZwGetNextThread(
        proc_handle: HANDLE,
        thread_handle: HANDLE,
        access: ACCESS_MASK,
        attr: ULONG,
        flags: ULONG,
        new_thread_handle: PHANDLE,
    ) -> NTSTATUS;
}