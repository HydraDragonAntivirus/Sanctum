//! This module handles callback implementations and and other function related to processes.

use alloc::{string::String, vec::Vec};
use core::{
    ffi::c_void,
    iter::once,
    ptr::{null_mut, slice_from_raw_parts},
    sync::atomic::Ordering,
    time::Duration,
};
use shared_no_std::driver_ipc::{HandleObtained, ProcessStarted, ProcessTerminated};
use wdk::println;
use wdk_sys::{
    _IMAGE_INFO,
    _MODE::KernelMode,
    _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS,
    _UNICODE_STRING, APC_LEVEL, HANDLE, LARGE_INTEGER, NTSTATUS, OB_CALLBACK_REGISTRATION,
    OB_FLT_REGISTRATION_VERSION, OB_OPERATION_HANDLE_CREATE, OB_OPERATION_HANDLE_DUPLICATE,
    OB_OPERATION_REGISTRATION, OB_PRE_OPERATION_INFORMATION, OB_PREOP_CALLBACK_STATUS, PEPROCESS,
    PROCESS_ALL_ACCESS, PS_CREATE_NOTIFY_INFO, PsProcessType, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
    TRUE, UNICODE_STRING,
    ntddk::{
        KeDelayExecutionThread, KeGetCurrentIrql, ObOpenObjectByPointer, ObRegisterCallbacks,
        PsGetCurrentProcessId, PsGetProcessId, PsRemoveLoadImageNotifyRoutine,
        PsSetLoadImageNotifyRoutine, RtlInitUnicodeString,
    },
};

use crate::{
    DRIVER_MESSAGES, REGISTRATION_HANDLE, core::process_monitor::ProcessMonitor,
    device_comms::ImageLoadQueueForInjector, utils::unicode_to_string,
};

/// Callback function for a new process being created on the system.
pub unsafe extern "C" fn process_create_callback(
    process: PEPROCESS,
    pid: HANDLE,
    create_info: *mut PS_CREATE_NOTIFY_INFO,
) {
    //
    // If `created` is not a null pointer, this means a new process was started, and you can query the
    // args for information about the newly spawned process.
    //
    // In the event that `create` is null, it means a process was terminated.
    //

    if !create_info.is_null() {
        // process started

        let image_name = unicode_to_string((*create_info).ImageFileName);
        let command_line = unicode_to_string((*create_info).CommandLine);
        let parent_pid = (*create_info).ParentProcessId as u64;
        // (*create_info).
        let pid = pid as u64;

        if image_name.is_err() || command_line.is_err() {
            return;
        }

        // todo was trying to do this before!
        // let mut peprocess: PEPROCESS = null_mut();
        // let mut proc_name: PUNICODE_STRING = null_mut();
        // unsafe { PsLookupProcessByProcessId(pid as *mut _, &mut peprocess) };
        // unsafe { SeLocateProcessImageName(peprocess, &mut proc_name) };

        let mut process_handle: HANDLE = null_mut();
        let _ = unsafe {
            ObOpenObjectByPointer(
                process as *mut _,
                0,
                null_mut(),
                PROCESS_ALL_ACCESS,
                *PsProcessType,
                KernelMode as _,
                &mut process_handle,
            )
        };

        // Set both bits: EnableReadVmLogging (bit 0) and EnableWriteVmLogging (bit 1)
        let mut logging_info = ProcessLoggingInformation { flags: 0x03 };
        let result = unsafe {
            ZwSetInformationProcess(
                process_handle,
                87,
                &mut logging_info as *mut _ as *mut _,
                size_of::<ProcessLoggingInformation>() as _,
            )
        };

        let process_started = ProcessStarted {
            image_name: image_name.unwrap().replace("\\??\\", ""),
            command_line: command_line.unwrap().replace("\\??\\", ""),
            parent_pid,
            pid,
        };

        if process_started.image_name.contains("otepad")
            || process_started.image_name.contains("alware.ex")
        {
            println!(
                "[sanctum] [i] Process of interest created, pid: {}, ppid: {}",
                pid, parent_pid
            );

            // todo this is buggy af ?
            if let Err(e) = ProcessMonitor::onboard_new_process(&process_started) {
                println!("[sanctum] [-] Error onboarding new process to PM. {:?}", e)
            };
        }

        // Attempt to dereference the DRIVER_MESSAGES global; if the dereference is successful,
        // add the relevant data to the queue
        // if !DRIVER_MESSAGES.load(Ordering::SeqCst).is_null() {
        //     let obj = unsafe { &mut *DRIVER_MESSAGES.load(Ordering::SeqCst) };
        //     obj.add_process_creation_to_queue(process_started);
        // } else {
        //     println!("[sanctum] [-] Driver messages is null");
        // };
    } else {
        // process terminated

        let pid = pid as u64;
        let process_terminated = ProcessTerminated { pid };

        // println!("[sanctum] [-] Process terminated, {:?}", process_terminated);

        // Attempt to dereference the DRIVER_MESSAGES global; if the dereference is successful,
        // add the relevant data to the queue
        if !DRIVER_MESSAGES.load(Ordering::SeqCst).is_null() {
            let obj = unsafe { &mut *DRIVER_MESSAGES.load(Ordering::SeqCst) };
            obj.add_process_termination_to_queue(process_terminated);
        } else {
            println!("[sanctum] [-] Driver messages is null");
        };
    }
}

pub struct ProcessHandleCallback {}

impl ProcessHandleCallback {
    pub fn register_callback() -> Result<(), NTSTATUS> {
        // IRQL <= APC_LEVEL required for ObRegisterCallbacks
        let irql = unsafe { KeGetCurrentIrql() };
        if irql as u32 > APC_LEVEL {
            return Err(1);
        }

        // todo will need a microsoft issues 'altitude'
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request
        let mut callback_registration = OB_CALLBACK_REGISTRATION::default();
        let mut altitude = UNICODE_STRING::default();
        let altitude_str = "327146";
        let altitude_str = altitude_str
            .encode_utf16()
            .chain(once(0))
            .collect::<Vec<_>>();
        unsafe { RtlInitUnicodeString(&mut altitude, altitude_str.as_ptr()) };

        // operation registration
        let mut operation_registration = OB_OPERATION_REGISTRATION::default();
        operation_registration.ObjectType = unsafe { PsProcessType };
        operation_registration.Operations =
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operation_registration.PreOperation = Some(pre_process_handle_callback);

        // // assign to the callback registration
        callback_registration.Altitude = altitude;
        callback_registration.Version = OB_FLT_REGISTRATION_VERSION as u16;
        callback_registration.OperationRegistrationCount = 1;
        callback_registration.RegistrationContext = null_mut();
        callback_registration.OperationRegistration = &mut operation_registration;

        let mut reg_handle: *mut c_void = null_mut();

        let status = unsafe { ObRegisterCallbacks(&mut callback_registration, &mut reg_handle) };
        if status != STATUS_SUCCESS {
            println!(
                "[sanctum] [-] Unable to register callback for handle interception. Failed with code: {status}."
            );
            return Err(STATUS_UNSUCCESSFUL);
        }
        REGISTRATION_HANDLE.store(reg_handle as *mut _, Ordering::Relaxed);

        Ok(())
    }
}

/// Callback function to handle process handle request,s
/// TODO this needs updating to pause on handle, communicate with engine, and make a decision as per drawing
pub unsafe extern "C" fn pre_process_handle_callback(
    ctx: *mut c_void,
    oi: *mut OB_PRE_OPERATION_INFORMATION,
) -> OB_PREOP_CALLBACK_STATUS {
    return OB_PREOP_SUCCESS;
    // todo pick up from here after thread testing

    // println!("Inside callback for handle. oi: {:?}", oi);

    // Check the inbound pointer is valid before attempting to dereference it. We will return 1 as an error code
    if oi.is_null() {
        return 1;
    }

    let p_target_process = (*oi).Object as PEPROCESS;
    let target_pid = PsGetProcessId(p_target_process);
    let source_pid = PsGetCurrentProcessId();

    let desired_access = (*(*oi).Parameters).CreateHandleInformation.DesiredAccess;
    let og_desired_access = (*(*oi).Parameters)
        .CreateHandleInformation
        .OriginalDesiredAccess;

    // if target_pid as u64 == 5228 && source_pid as u64 != 9552 {
    //     println!("[sanctum] [i] Sending PROCESS STARTED INFO {:?}", HandleObtained {
    //         source_pid: source_pid as u64,
    //         dest_pid: target_pid as u64,
    //         rights_desired: og_desired_access,
    //         rights_given: desired_access,
    //     });

    // }

    if !DRIVER_MESSAGES.load(Ordering::SeqCst).is_null() {
        let obj = unsafe { &mut *DRIVER_MESSAGES.load(Ordering::SeqCst) };
        obj.add_process_handle_to_queue(HandleObtained {
            source_pid: source_pid as u64,
            dest_pid: target_pid as u64,
            rights_desired: og_desired_access,
            rights_given: desired_access,
        });
    } else {
        println!("[sanctum] [-] Driver messages is null");
    };

    OB_PREOP_SUCCESS
}

#[repr(C)]
pub union ProcessLoggingInformation {
    pub flags: u32,
}

unsafe extern "system" {
    fn ZwSetInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
    ) -> NTSTATUS;
}

pub fn register_image_load_callback() -> NTSTATUS {
    // Register the ImageLoadQueueForInjector which will instantiate the Grt containing the mutex for async
    // access.
    ImageLoadQueueForInjector::init();
    unsafe { PsSetLoadImageNotifyRoutine(Some(image_load_callback)) }
}

pub fn unregister_image_load_callback() {
    let _ = unsafe { PsRemoveLoadImageNotifyRoutine(Some(image_load_callback)) };
}

/// The callback function for image load events (exe, dll)
///
/// # Remarks
/// This routine will be called by the operating system to notify the driver when a driver image or a user image
/// (for example, a DLL or EXE) is mapped into virtual memory. The operating system invokes this routine after an
/// image has been mapped to memory, but before its entrypoint is called.
///
/// **IMPORTANT NOTE:** The operating system does not call load-image notify routines when sections created with the `SEC_IMAGE_NO_EXECUTE`
/// attribute are mapped to virtual memory. This shouldn't affect early bird techniques - but WILL need attention in the future
/// as this attribute could be used in process hollowing etc to avoid detection with our filter callback here.
///
/// todo One way to defeat this once I get round to it would be hooking the NTAPI with our DLL and refusing any attempt to use that
/// parameter; or we could dynamically change it at runtime. My Ghost Hunting technique should allow us to detect a threat actor
/// trying to use direct syscalls etc to bypass the hook.
///
/// Some links on this:
///
/// - https://www.secforce.com/blog/dll-hollowing-a-deep-dive-into-a-stealthier-memory-allocation-variant/
/// - https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-ii-insights-from-moneta
extern "C" fn image_load_callback(
    image_name: *mut _UNICODE_STRING,
    pid: HANDLE,
    image_info: *mut _IMAGE_INFO,
) {

    // todo can i use this callback in an attempt to detect DLL SOH?? :)

    // I guess these should never be null
    if image_info.is_null() || image_name.is_null() {
        return;
    }

    // Check that we aren't dealing with a driver load, we dont care about those for now
    if pid.is_null() {
        return;
    }

    // Check the inbound pointers
    if image_info.is_null() || image_name.is_null() {
        println!(
            "[sanctum] [-] Pointers were null in image_load_callback, and this is unexpected."
        );
        return;
    }

    // SAFETY: Pointers validated above
    let image_name = unsafe { *image_name };
    let image_info = unsafe { *image_info };

    let name_slice = slice_from_raw_parts(image_name.Buffer, (image_name.Length / 2) as usize);
    let name = String::from_utf16_lossy(unsafe { &*name_slice }).to_lowercase();

    // For now only concern ourselves with image loads where its an exe, except in the event its the sanctum EDR DLL -
    // see below comments for why.
    if name.contains(".dll") && !name.contains("sanctum.dll") {
        return;
    }

    // Now we are into the 'meat' of the callback routine. To see why we are doing what we are doing here,
    // please refer to the function definition. In a nutshell, queue the process creation, the usermode engine
    // will poll the driver for new processes; the driver will wait for notification our DLL is injected.
    //
    // We can get around waiting on an IOCTL to come back from usermode by seeing when "sanctum.dll" is mapped into
    // the PID. This presents one potential 'vulnerability' in that a malicious process could attempt to inject a DLL
    // named "sanctum.dll" into our process; we can get around this by maintaining a second Grt mutex which contains
    // the PIDs that are pending the sanctum dll being injected. In the event the PID has been removed (aka we have a
    // sanctum.dll injected in) we know either foul play is detected (a TA is trying to exploit this vulnerability in the
    // implementation), or a unforeseen sanctum related error has occurred.
    //
    // **NOTE**: Handling the draining of the `ImageLoadQueueForInjector` and adding the pid to the pending `Grt` is handled
    // in the `driver_communication` module - we dont need to worry about that implementation here, it will happen here
    // as if 'by magic'. See the implementation there for more details.
    //
    // In either case; we can freeze the process and alert the user to possible malware / dump the process / kill the process
    // etc.
    //
    // Depending on performance; we could also fast hash the "sanctum.dll"  bytes to see whether it matches the expected DLL -
    // this *may* be more performant than accessing the Grt, but for now, this works.
    //
    // todo would be nice to make an API for this as we will likely want to use this in various other places in the EDR.

    // todo the match here should be done on the full path to accidental prevent name collisions
    if name.ends_with("sanctum.dll") {
        if ImageLoadQueueForInjector::remove_pid_from_injection_waitlist(pid as usize).is_err() {
            // todo handle threat detection here
        }
    }

    // For now, only inject into these processes whilst we test
    if !name.contains("malware.exe")
    {
        return;
    }

    ImageLoadQueueForInjector::queue_process_for_usermode(pid as usize);

    let delay_as_duration = Duration::from_millis(300);
    let mut thread_sleep_time = LARGE_INTEGER {
        QuadPart: -((delay_as_duration.as_nanos() / 100) as i64),
    };

    loop {
        // todo I'd rather use a KEVENT than a loop - just need to think about the memory model for it.
        // Tried implementing this now, but as im at POC phase it required quite a bit of a refactor, so i'll do this in the
        // future more likely. Leaving the todo in to work on this later :)
        // The least we can do is make the threat alertable so we aren't starving too many resources.
        let _ =
            unsafe { KeDelayExecutionThread(KernelMode as _, TRUE as _, &mut thread_sleep_time) };

        if !ImageLoadQueueForInjector::pid_in_waitlist(pid as usize) {
            println!("[sanctum] [i] DLL injected into PID: {}!", pid as usize);
            break;
        }
    }
}
