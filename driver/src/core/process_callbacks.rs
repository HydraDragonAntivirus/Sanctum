//! This module handles callback implementations and and other function related to processes.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    arch::asm,
    ffi::c_void,
    iter::once,
    ptr::{null_mut, slice_from_raw_parts},
    sync::atomic::Ordering,
    time::Duration,
};
use shared_no_std::driver_ipc::{HandleObtained, ProcessStarted};
use wdk::{nt_success, println};
use wdk_sys::{
    _IMAGE_INFO,
    _MODE::{KernelMode, UserMode},
    _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS,
    _SECTION_INHERIT::ViewUnmap,
    _UNICODE_STRING, APC_LEVEL, FILE_EXECUTE, FILE_NON_DIRECTORY_FILE, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_SYNCHRONOUS_IO_NONALERT, HANDLE, IO_STATUS_BLOCK, KAPC, MEM_COMMIT, MEM_RESERVE, NTSTATUS,
    OB_CALLBACK_REGISTRATION, OB_FLT_REGISTRATION_VERSION, OB_OPERATION_HANDLE_CREATE,
    OB_OPERATION_HANDLE_DUPLICATE, OB_OPERATION_REGISTRATION, OB_PRE_OPERATION_INFORMATION,
    OB_PREOP_CALLBACK_STATUS, OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE, OBJECT_ATTRIBUTES,
    PAGE_EXECUTE_READ, PAGE_READWRITE, PEPROCESS, PKTHREAD, PRKAPC, PROCESS_ALL_ACCESS,
    PS_CREATE_NOTIFY_INFO, PVOID, PsProcessType, SEC_IMAGE, SECTION_MAP_EXECUTE, SECTION_MAP_READ,
    SECTION_MAP_WRITE, STANDARD_RIGHTS_ALL, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, SYNCHRONIZE, TRUE,
    UNICODE_STRING,
    ntddk::{
        KeDelayExecutionThread, KeGetCurrentIrql, ObOpenObjectByPointer, ObRegisterCallbacks,
        PsGetCurrentProcessId, PsGetProcessId, PsRemoveLoadImageNotifyRoutine,
        PsSetLoadImageNotifyRoutine, RtlCopyMemoryNonTemporal, RtlInitUnicodeString,
        ZwAllocateVirtualMemory, ZwClose, ZwCreateSection, ZwMapViewOfSection, ZwOpenFile,
    },
};

use crate::{
    DRIVER_MESSAGES, REGISTRATION_HANDLE,
    alt_syscalls::AltSyscalls,
    core::process_monitor::{LoadedModule, MONITORED_FN_PTRS, ProcessMonitor, SensitiveAPI},
    device_comms::ImageLoadQueueForInjector,
    ffi::{
        InitializeObjectAttributes, KeInitializeApc, KeInsertQueueApc, PKNORMAL_ROUTINE,
        PsGetCurrentProcess,
    },
    utils::{duration_to_large_int, get_process_name, unicode_to_string},
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
        //
        // process started
        //

        let image_name = unicode_to_string(unsafe { (*create_info).ImageFileName });
        let command_line = unicode_to_string(unsafe { (*create_info).CommandLine });
        let parent_pid = unsafe { (*create_info).ParentProcessId as u32 };
        let pid = pid as u32;

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
        let _ = unsafe {
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

        // Add the new process to the monitor
        if let Err(e) = ProcessMonitor::onboard_new_process(&process_started) {
            println!("[sanctum] [-] Error onboarding new process to PM. {:?}", e)
        };
    } else {
        //
        // process terminated
        //

        let pid = pid as u32;
        ProcessMonitor::remove_process(pid);
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

    // In the event it is a DLL load, we want to grab & track its mappings
    if name.contains(".dll") && !name.contains("sanctum.dll") {
        // todo hash check on the sanctum DLL to make sure an adversary isn't calling their malicious DLL `sanctum.dll`
        // which would interfere with what we are doing in this segment.

        // todo is it re-loading NTDLL when NTDLL already exists in the process? Bad, we want to stop this and report
        // on it.

        let lm = LoadedModule::new(image_info.ImageBase as _, image_info.ImageSize as _);

        ProcessMonitor::add_loaded_module(lm, &name, pid as u32);

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

    // todo the match here should be done on the full path to accidental prevent name collisions / threat vectors that way
    if name.ends_with("sanctum.dll") {
        println!(
            "******************* SANCTUM DLL INJECTED, proc: {}",
            get_process_name()
        );
        if ImageLoadQueueForInjector::remove_pid_from_injection_waitlist(pid as usize).is_err() {
            // todo handle threat detection here
        }

        // Track in ProcessMonitor
        let lm = LoadedModule::new(image_info.ImageBase as _, image_info.ImageSize as _);
        ProcessMonitor::add_loaded_module(lm, &name, pid as u32);

        // We can now enable alt syscalls on this process as the DLL is loaded so techniques like Ghost Hunting etc shouldn't
        // cause issues.
        let mut k_thread: *const c_void = null_mut();
        unsafe {
            asm!(
                "mov {}, gs:[0x188]",
                out(reg) k_thread,
            );
        }
        AltSyscalls::configure_process_for_alt_syscalls(k_thread as *mut _);
        return;
    }

    if !name.ends_with(".exe") {
        return;
    }

    // let mut k_thread: *const c_void = null_mut();
    // unsafe {
    //     asm!(
    //         "mov {}, gs:[0x188]",
    //         out(reg) k_thread,
    //     );
    // }

    // if k_thread.is_null() {
    //     println!("[-] [Sanctum] No KTHREAD discovered.");
    //     return;
    // }

    // println!("Doing the thing, img name: {name}");
    // if let Some(path_addr) = write_dl_path() {
    //     register_apc_for_sanctum_dll_load(k_thread as *mut _, path_addr);
    // }

    // For now, only inject into these processes whilst we test
    // if !name.contains("malware.exe") {
    //     return;
    // }

    ImageLoadQueueForInjector::queue_process_for_usermode(pid as usize);

    let mut thread_sleep_time = duration_to_large_int(Duration::from_secs(1));

    loop {
        // todo I'd rather use a KEVENT than a loop - just need to think about the memory model for it.
        // Tried implementing this now, but as im at POC phase it required quite a bit of a refactor, so i'll do this in the
        // future more likely. Leaving the todo in to work on this later :)
        // The least we can do is make the threat alertable so we aren't starving too many resources.
        let _ =
            unsafe { KeDelayExecutionThread(KernelMode as _, TRUE as _, &mut thread_sleep_time) };

        if !ImageLoadQueueForInjector::pid_in_waitlist(pid as usize) {
            break;
        }

        println!("In loop for: {}. PID: {}", get_process_name(), unsafe {
            PsGetCurrentProcessId() as u32
        });

        if name.to_ascii_lowercase().contains("backgroundtask") {
            break;
        }
    }
}

fn register_apc_for_sanctum_dll_load(thread: PKTHREAD, dll_allocation_addr: *mut c_void) {
    // todo turn this into a helper API maybe in utils
    let mut apc = Box::new(KAPC::default());
    let p_normal_routine = MONITORED_FN_PTRS.load(Ordering::SeqCst);
    if p_normal_routine.is_null() {
        println!("[sanctum] [-] p_normal_routine was null. Cannot continue");
        return;
    }

    let mut addr: *const c_void = null_mut();
    unsafe { &*p_normal_routine }
        .inner
        .iter()
        .for_each(|entry| {
            if entry.1.1 == SensitiveAPI::LoadLibraryW {
                addr = *entry.0 as *const c_void;
            }
        });

    if addr.is_null() {
        println!("[sanctum] [-] Did not get the address of LoadLibraryW");
        return;
    }

    let pid = unsafe { PsGetCurrentProcessId() } as u32;
    println!(
        "[{} | {pid}], LLW addr: {addr:p}, alloc addr: {dll_allocation_addr:p}",
        get_process_name()
    );

    unsafe {
        KeInitializeApc(
            &mut *apc,
            thread,
            crate::ffi::_KAPC_ENVIRONMENT::OriginalApcEnvironment,
            Some(apc_callback_inject_sanctum),
            None,
            Some(addr),
            UserMode as i8,
            dll_allocation_addr,
        );
    }

    let res = unsafe { KeInsertQueueApc(&mut *apc, null_mut(), null_mut(), 0) };
    if res == 0 {
        println!("FAIL Result of KeInsertQueueApc: {res:#X}");
        return;
    }

    // todo mem leak? needs ref counting?
    let raw = Box::into_raw(apc);
}

/// The function that runs in kernel mode on our APC callback occurring. This function will allow
/// us to alter `NormalContext`, `SystemArgument1`, `SystemArgument2` which will be passed to the normal
/// routine.
unsafe extern "C" fn apc_callback_inject_sanctum(
    apc: PRKAPC,
    normal_routine: PKNORMAL_ROUTINE,
    normal_context: *mut PVOID,
    system_arg_1: *mut PVOID,
    system_arg_2: *mut PVOID,
) {
}

unsafe extern "C" fn normal_routine(arg1: PVOID, arg2: PVOID, arg3: PVOID) {
    if unsafe { KeGetCurrentIrql() } >= APC_LEVEL as u8 {
        println!("[sanctum] [-] IRQL too high for callback injecting sanctum.dll");
        return;
    }

    let mut process_handle: HANDLE = null_mut();
    let cur_proc = unsafe { PsGetCurrentProcess() };
    if cur_proc.is_null() {
        println!("[sanctum] [-] Current process was null in apc_callback_inject_sanctum");
        return;
    }
    let status = unsafe {
        ObOpenObjectByPointer(
            cur_proc as *mut _,
            OBJ_KERNEL_HANDLE,
            null_mut(),
            STANDARD_RIGHTS_ALL,
            null_mut(),
            KernelMode as _,
            &mut process_handle,
        )
    };

    if !nt_success(status) || process_handle.is_null() {
        println!(
            "[sanctum] [-] Error calling ObOpenObjectByPointer in dll injection callback: {status:#X}, handle: {process_handle:?}."
        );
        return;
    }

    let path: Vec<u16> = r"\??\C:\Users\flux\AppData\Roaming\Sanctum\sanctum.dll"
        .encode_utf16()
        .chain(once(0))
        .collect();
    let mut path_unicode = UNICODE_STRING::default();
    unsafe {
        RtlInitUnicodeString(&mut path_unicode, path.as_ptr());
    }
    let mut file: HANDLE = null_mut();
    let mut dll_path_oa = OBJECT_ATTRIBUTES::default();
    let _ = unsafe {
        InitializeObjectAttributes(
            &mut dll_path_oa,
            &mut path_unicode,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            null_mut(),
            null_mut(),
        )
    };

    let mut iosb = IO_STATUS_BLOCK::default();

    let status = unsafe {
        ZwOpenFile(
            &mut file,
            FILE_READ_DATA | FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &mut dll_path_oa,
            &mut iosb,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
    };
    if !nt_success(status) {
        let _ = unsafe { ZwClose(process_handle) };
        println!("[sanctum] [-] FAILED to open sanctum DLL. Code: {status:#X}");
        return;
    }

    // Create new section for DLL mapping
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

    let mut dll_section_handle: HANDLE = null_mut();

    let status = unsafe {
        ZwCreateSection(
            &mut dll_section_handle,
            SECTION_MAP_WRITE | SECTION_MAP_EXECUTE | SECTION_MAP_READ,
            &mut oa,
            null_mut(),
            PAGE_EXECUTE_READ,
            SEC_IMAGE,
            file,
        )
    };
    if !nt_success(status) {
        let _ = unsafe { ZwClose(process_handle) };
        println!("[sanctum] [-] Failed to create section. {status:#X}");
        return;
    }

    // Map the DLL on the section
    let mut dll_base: *mut c_void = null_mut();
    let mut view_size: u64 = 0;
    let status = unsafe {
        ZwMapViewOfSection(
            dll_section_handle,
            process_handle,
            &mut dll_base,
            0,
            0,
            null_mut(),
            &mut view_size,
            ViewUnmap,
            0,
            PAGE_EXECUTE_READ,
        )
    };

    if !nt_success(status) {
        let _ = unsafe { ZwClose(process_handle) };
        let _ = unsafe { ZwClose(dll_section_handle) };
        println!("[sanctum] [-] Failed ZwMapViewOfSection. {status:#X}");
        return;
    }

    println!("Mapped DLL at base: {dll_base:p}, sz: {view_size}");
}

fn write_dl_path() -> Option<*mut c_void> {
    let mut base: *mut c_void = null_mut();
    let path: Vec<u16> = r"C:\Users\flux\AppData\Roaming\Sanctum\sanctum.dll"
        .encode_utf16()
        .chain(once(0))
        .collect();

    let path_len = path.len() as u64 * 2;
    let mut sz: u64 = path_len;

    let status = unsafe {
        ZwAllocateVirtualMemory(
            (-1isize) as HANDLE,
            &mut base,
            0,
            &mut sz,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if !nt_success(status) {
        println!("[sanctum] [-] Failed to allocate VM for DLL path. Status: {status:#X}");
        return None;
    }

    unsafe { RtlCopyMemoryNonTemporal(base, path.as_ptr() as *const c_void, path_len) };

    Some(base)
}
