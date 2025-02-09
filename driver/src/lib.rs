// Sanctum Windows Kernel Mode Driver written in Rust
// Date: 12/10/2024
// Author: flux
//      GH: https://github.com/0xflux
//      Blog: https://fluxsec.red/

#![no_std]
extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

use core::{processes::{process_create_callback, ProcessHandleCallback}, syscall_handlers::{register_syscall_hooks, SyscallHandler}, threads::{set_thread_creation_callback, thread_callback}};
use ::core::{ffi::c_void, ptr::null_mut, sync::atomic::{AtomicPtr, Ordering}};
use alloc::{boxed::Box, format};
use ffi::IoGetCurrentIrpStackLocation;
use device_comms::{ioctl_check_driver_compatibility, ioctl_handler_get_kernel_msg_len, ioctl_handler_ping, ioctl_handler_ping_return_struct, ioctl_handler_send_kernel_msgs_to_userland, DriverMessagesWithMutex};
use shared_no_std::{constants::{DOS_DEVICE_NAME, NT_DEVICE_NAME, VERSION_DRIVER}, ioctl::{SANC_IOCTL_CHECK_COMPATIBILITY, SANC_IOCTL_DRIVER_GET_MESSAGES, SANC_IOCTL_DRIVER_GET_MESSAGE_LEN, SANC_IOCTL_PING, SANC_IOCTL_PING_WITH_STRUCT}};
use utils::{Log, LogLevel, ToU16Vec};
use wdk::{nt_success, println};
use wdk_mutex::{grt::Grt, kmutex::KMutex};
use wdk_sys::{
    ntddk::{IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink, IofCompleteRequest, ObUnRegisterCallbacks, PsRemoveCreateThreadNotifyRoutine, PsSetCreateProcessNotifyRoutineEx, RtlInitUnicodeString}, DEVICE_OBJECT, DO_BUFFERED_IO, DRIVER_OBJECT, FALSE, FILE_DEVICE_SECURE_OPEN, FILE_DEVICE_UNKNOWN, IO_NO_INCREMENT, IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, NTSTATUS, PCUNICODE_STRING, PDEVICE_OBJECT, PIRP, PUNICODE_STRING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, TRUE, UNICODE_STRING, _IO_STACK_LOCATION
};

mod ffi;
mod utils;
mod device_comms;
mod core;

use wdk_alloc::WdkAllocator;
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

//
// STATICS
// Not ideal; but as DriverEntry exists whilst the driver is still loaded in memory, lifetimes etc
// wont ensure certain parts of memory isn't deallocated.
//

/// An atomic pointer to the DriverMessagesWithSpinLock struct so that it can be used anywhere in the 
/// kernel.
static DRIVER_MESSAGES: AtomicPtr<DriverMessagesWithMutex> = AtomicPtr::new(null_mut());
static DRIVER_MESSAGES_CACHE: AtomicPtr<DriverMessagesWithMutex> = AtomicPtr::new(null_mut());
static DRIVER_CONTEXT_PTR: AtomicPtr<DeviceContext> = AtomicPtr::new(null_mut());
static REGISTRATION_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static AP_DEVICE_OBJECT: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(null_mut());

struct DeviceContext {
    log_file_mutex: KMutex<u32>,
}

/// DriverEntry is required to start the driver, and acts as the main entrypoint
/// for our driver.
#[export_name = "DriverEntry"] // WDF expects a symbol with the name DriverEntry
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    println!("[sanctum] [i] Starting Sanctum driver... Version: {}", VERSION_DRIVER);

    if let Err(e) = Grt::init() {
        println!("Error creating Grt!: {:?}", e);
        return STATUS_UNSUCCESSFUL;
    }

    let status = configure_driver(driver, registry_path as *mut _);

    status
}


/// This deals with setting up the driver and any callbacks / configurations required
/// for its operation and lifetime.
pub unsafe extern "C" fn configure_driver(
    driver: *mut DRIVER_OBJECT,
    _registry_path: PUNICODE_STRING,
) -> NTSTATUS {
    println!("[sanctum] [i] running sanctum_entry...");
    let log = Log::new();
    log.log(LogLevel::Info, "Sanctum starting...");

    //
    // Initialise the global DRIVER_MESSAGES variable
    //
    let messages = Box::new(DriverMessagesWithMutex::new());
    let messages_cache = Box::new(DriverMessagesWithMutex::new());
    // take ownership of the pointer to the messages struct; the pointer shouldn't change as the 
    // struct contains a pointer to the vec, that is allowed to change.
    DRIVER_MESSAGES.store(Box::into_raw(messages), Ordering::SeqCst);
    DRIVER_MESSAGES_CACHE.store(Box::into_raw(messages_cache), Ordering::SeqCst);


    log.log_to_userland(format!("Starting Sanctum driver... Version: {}", VERSION_DRIVER));

    //
    // Configure the strings required for symbolic links and naming
    //
    let mut dos_name = UNICODE_STRING::default();
    let mut nt_name = UNICODE_STRING::default();

    let dos_name_u16 = DOS_DEVICE_NAME.to_u16_vec();
    let device_name_u16 = NT_DEVICE_NAME.to_u16_vec();
    
    RtlInitUnicodeString(&mut dos_name, dos_name_u16.as_ptr());
    RtlInitUnicodeString(&mut nt_name, device_name_u16.as_ptr());


    //
    // Create the device
    //
    let mut device_object: PDEVICE_OBJECT = null_mut();
    
    let res = IoCreateDevice(
        driver,
        size_of::<DeviceContext>() as u32,
        &mut nt_name,
        FILE_DEVICE_UNKNOWN, // If a type of hardware does not match any of the defined types, specify a value of either FILE_DEVICE_UNKNOWN
        FILE_DEVICE_SECURE_OPEN,
        0,
        &mut device_object,
    );
    if !nt_success(res) {
        println!("[sanctum] [-] Unable to create device via IoCreateDevice. Failed with code: {res}.");
        return res;
    }

    // store a global pointer to the device object
    // AP_DEVICE_OBJECT.store(device_object, Ordering::Relaxed);

    // let device_extension = (*device_object).DeviceExtension as *mut DeviceContext;
    // (*device_extension) = DeviceContext {
    //     log_file_mutex: KMutex::new(0u32).unwrap(),
    // };

    // // store the device context in the global
    // DRIVER_CONTEXT_PTR.store((*device_object).DeviceExtension as *mut _, Ordering::Relaxed);
    

    //
    // Create the symbolic link
    //
    let res = IoCreateSymbolicLink(&mut dos_name, &mut nt_name);
    if res != 0 {
        println!("[sanctum] [-] Failed to create driver symbolic link. Error: {res}");

        driver_exit(driver); // cleanup any resources before returning
        return STATUS_UNSUCCESSFUL;
    }


    //
    // Configure the drivers general callbacks
    //
    (*driver).MajorFunction[IRP_MJ_CREATE as usize] = Some(sanctum_create_close); // todo can authenticate requests coming from x
    (*driver).MajorFunction[IRP_MJ_CLOSE as usize] = Some(sanctum_create_close);
    // (*driver).MajorFunction[IRP_MJ_WRITE as usize] = Some(handle_ioctl);
    (*driver).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(handle_ioctl);
    (*driver).DriverUnload = Some(driver_exit);
    

    //
    // Core callback functions for the EDR
    //

    // Custom syscall kernel-side hook and ensuring the GRT (wdk_mutex) is set up for the syscall hooks
    if register_syscall_hooks().is_err() {
        println!("[sanctum] [-] register_syscall_hooks failed.");
        return 1;
    }

    // Thread interception
    set_thread_creation_callback();

    // Intercepting process creation
    let res = PsSetCreateProcessNotifyRoutineEx(Some(process_create_callback), FALSE as u8);
    if res != STATUS_SUCCESS {
        println!("[sanctum] [-] Unable to create device via IoCreateDevice. Failed with code: {res}.");
        return res;
    }

    // Requests for a handle
    if let Err(e) = ProcessHandleCallback::register_callback() {
        return e;
    }

    // Specifies the type of buffering that is used by the I/O manager for I/O requests that are sent to the device stack.
    (*device_object).Flags |= DO_BUFFERED_IO;

    STATUS_SUCCESS
}


/// Driver unload functions when it is to exit.
///
/// # Safety
///
/// This function makes use of unsafe code.
extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) {

    // rm symbolic link
    let mut dos_name = UNICODE_STRING::default();
    let dos_name_u16 = DOS_DEVICE_NAME.to_u16_vec();
    unsafe {
        RtlInitUnicodeString(&mut dos_name, dos_name_u16.as_ptr());
    }
    let _ = unsafe { IoDeleteSymbolicLink(&mut dos_name) };


    //
    // Unregister callback routines 
    //

    // drop the callback for new process interception
    let res = unsafe { PsSetCreateProcessNotifyRoutineEx(Some(process_create_callback), TRUE as u8) };
    if res != STATUS_SUCCESS {
        println!("[sanctum] [-] Error removing PsSetCreateProcessNotifyRoutineEx from callback routines. Error: {res}");
    }

    // drop the callback for new thread interception
    let res = unsafe { PsRemoveCreateThreadNotifyRoutine(Some(thread_callback)) };
    if res != STATUS_SUCCESS {
        println!("[sanctum] [-] Error removing PsSetCreateProcessNotifyRoutineEx from callback routines. Error: {res}");
    }

    // drop the callback routines for process handle interception
    unsafe {
        if !REGISTRATION_HANDLE.load(Ordering::Relaxed).is_null() {
            ObUnRegisterCallbacks(REGISTRATION_HANDLE.load(Ordering::Relaxed));
            REGISTRATION_HANDLE.store(null_mut(), Ordering::Relaxed);
        }
    }

    // remove the alt syscall handler changes we made to threads
    {
        let mtx = Grt::get_fast_mutex("syscall_handler").expect("Could not get syscall_handler fast mutex.");
        let lock: wdk_mutex::fast_mutex::FastMutexGuard<'_, SyscallHandler> = mtx.lock().unwrap();
        lock.remove_alt_syscall_handler_from_threads();
    }

    // drop the driver messages
    let ptr = DRIVER_MESSAGES.load(Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }

    // drop the message cache
    let ptr = DRIVER_MESSAGES_CACHE.swap(null_mut(), Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
    
    if let Err(e) = unsafe { Grt::destroy() } {
        println!("Error destroying: {:?}", e);
    }

    // delete the device
    unsafe { IoDeleteDevice((*driver).DeviceObject);}

    println!("[sanctum] driver unloaded successfully...");
}


unsafe extern "C" fn sanctum_create_close(_device: *mut DEVICE_OBJECT, pirp: PIRP) -> NTSTATUS {
    
    (*pirp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
    (*pirp).IoStatus.Information = 0;
    IofCompleteRequest(pirp, IO_NO_INCREMENT as i8);

    println!("[sanctum] [i] IRP received...");
    
    STATUS_SUCCESS
}

/// Device IOCTL input handler.
///
/// This function will process IOCTL commands as they come into the driver and executing the relevant actions.
///
/// # Arguments
///
/// - '_device': Unused
/// - 'irp': A pointer to the I/O request packet (IRP) that contains information about the request
unsafe extern "C" fn handle_ioctl(_device: *mut DEVICE_OBJECT, pirp: PIRP) -> NTSTATUS {
    let p_stack_location: *mut _IO_STACK_LOCATION = IoGetCurrentIrpStackLocation(pirp);

    if p_stack_location.is_null() {
        println!("[sanctum] [-] Unable to get stack location for IRP.");
        return STATUS_UNSUCCESSFUL;
    }

    let control_code = (*p_stack_location).Parameters.DeviceIoControl.IoControlCode; // IOCTL code

    // process the IOCTL based on its code, note that the functions implementing IOCTL's should
    // contain detailed error messages within the functions, returning a Result<(), NTSTATUS> this will
    // assist debugging exactly where an error has occurred, and not printing it at this level prevents
    // duplication.
    //
    // we still require calling IofCompleteRequest to return the IRP to the I/O manager otherwise we risk
    // causing the driver to hang.
    let result: NTSTATUS = match control_code {
        SANC_IOCTL_PING => {
            if let Err(e) = ioctl_handler_ping(p_stack_location, pirp){
                println!("[sanctum] [-] Error: {e}");
                e
            } else {
                STATUS_SUCCESS
            }
        },
        SANC_IOCTL_PING_WITH_STRUCT => {
            if let Err(e) = ioctl_handler_ping_return_struct(p_stack_location, pirp){
                println!("[sanctum] [-] Error: {e}");
                e
            } else {
                STATUS_SUCCESS
            }
        },
        SANC_IOCTL_CHECK_COMPATIBILITY => {
            if let Err(e) = ioctl_check_driver_compatibility(p_stack_location, pirp){
                println!("[sanctum] [-] Error: {e}");
                e
            } else {
                STATUS_SUCCESS
            }
        }
        SANC_IOCTL_DRIVER_GET_MESSAGE_LEN => {
            if let Err(_) = ioctl_handler_get_kernel_msg_len(pirp){
                STATUS_UNSUCCESSFUL
            } else {
                STATUS_SUCCESS
            }
        }
        SANC_IOCTL_DRIVER_GET_MESSAGES => {
            if let Err(_) = ioctl_handler_send_kernel_msgs_to_userland(pirp){
                STATUS_UNSUCCESSFUL
            } else {
                STATUS_SUCCESS
            }
            // STATUS_SUCCESS
        }

        _ => {
            println!("[sanctum] [-] IOCTL control code: {} not implemented.", control_code);
            STATUS_UNSUCCESSFUL
        }
    };

    // indicates that the caller has completed all processing for a given I/O request and 
    // is returning the given IRP to the I/O manager
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocompleterequest
    IofCompleteRequest(pirp, IO_NO_INCREMENT as i8);
    
    result
}