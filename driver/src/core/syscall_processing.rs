//! This module relates to the post-processing of system call's intercepted via the Alternate Syscalls technique.

use core::{
    ffi::c_void,
    mem::{self, MaybeUninit},
    ptr::null_mut,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
    time::Duration,
};

use alloc::{collections::vec_deque::VecDeque, string::ToString, vec::Vec};
use shared_no_std::ghost_hunting::{NtAllocateVirtualMemoryData, NtFunction, NtOpenProcessData, Syscall};
use wdk::{nt_success, println};
use wdk_mutex::{
    fast_mutex::FastMutexGuard,
    grt::Grt,
};
use wdk_sys::{
    ntddk::{
        KeDelayExecutionThread, KeWaitForSingleObject, ObReferenceObjectByHandle, ObfDereferenceObject, PsCreateSystemThread, PsGetCurrentProcessId, PsTerminateSystemThread
    }, CLIENT_ID, FALSE, HANDLE, KTRAP_FRAME, LARGE_INTEGER, STATUS_SUCCESS, THREAD_ALL_ACCESS, _KWAIT_REASON::Executive, _MODE::KernelMode
};

use crate::{alt_syscalls::{SSN_NT_ALLOCATE_VIRTUAL_MEMORY, SSN_NT_OPEN_PROCESS, SSN_NT_WRITE_VM}, core::process_monitor::ProcessMonitor, utils::{handle_to_pid, DriverError}};

/// Returns a borrowed view over stack argument slots saved in a `_KTRAP_FRAME`.
/// The slice elements are interpreted as raw pointer-width values (`*const c_void`)
/// so the caller can cast each slot appropriately.
/// 
/// **This does not allocate or copy.**
/// 
/// # Returns
/// A slice of length `n` over the stack slots starting at an ABI-dependent offset
/// from `ktrap.Rsp`. Each element is a pointer-width value (8 bytes on x64)
/// that may represent either a pointer or an integer value placed on the stack.
/// 
/// # Safety
/// - `ktrap.Rsp` must refer to a valid, readable stack frame with at least `n`
///   8-byte slots available.
/// - The returned slice aliases memory owned by the trapped thread; do **not**
///   persist it beyond immediate use, you must clone or copy any such data.
/// - If the slots correspond to **user-mode** stack memory, ensure you are at a
///   safe IRQL and use appropriate probing/copy patterns before dereferencing
///   user pointers. Creating the slice itself is safe, but dereferencing what it
///   points to may fault.
/// - Do **not** dereference `*const c_void` directly; cast to a concrete pointer type first.
/// - If you need any data to **persist** which is NOT copy, it must be cloned.
/// 
/// # Examples
/// ```ignore
/// // Borrow 2 stack slots (e.g., the 5th and 6th overall args if the first four were in regs)
/// let slots = unsafe { ktrap_get_stack_args(&ktrap_frame, 2) };
///
/// // Reading an integer value (<= 64 bits) that was passed on the stack:
/// let val_u32: u32 = slots[0] as u322;            // interpret slot value as integer
///
/// // Reading through a pointer that was on the stack:
/// let p_u32 = slots[1] as *const u32;             // cast the slot to a typed pointer
/// let deref_u32 = unsafe { *p_u32 };              // now dereference
/// ```
unsafe fn ktrap_get_stack_args<'a>(
    ktrap: &'a KTRAP_FRAME,
    n: usize,
) -> &'a [*const c_void] {
    // The offset to the start of the stack args as per ABI
    const STARTING_OFFSET: usize = 5;

    let base = unsafe { (ktrap.Rsp as *const *const c_void).add(STARTING_OFFSET) };
    unsafe { alloc::slice::from_raw_parts(base, n) }
}


/// Indicates whether the [`SyscallPostProcessor`] system is active or not. Active == true.
/// Using a static atomic as we cannot explicitly get a handle to a SyscallPostProcessor if it does not
/// exist, so checking will be hard. This static is internal to this module.
static SYSCALL_PP_ACTIVE: AtomicBool = AtomicBool::new(false);
/// A flag which condition is checked to determine whether the thread is running or not. Setting this to false
/// allows the thread to terminate itself.
static SYSCALL_CANCEL_THREAD: AtomicBool = AtomicBool::new(false);
static SYSCALL_THREAD_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

// #[derive(Debug)]
// pub enum Syscall {
//     NtOpenProcess(NtOpenProcess),
//     NtAllocateVirtualMemory(NtAllocateVirtualMemory),
// }

pub struct KernelSyscallIntercept {
    pub syscall: Syscall,
}

impl KernelSyscallIntercept {
    /// Creates a new [`KernelSyscallIntercept`] from an intercepted Alt Syscall,
    /// and pushes the captured data straight onto the queue for [`SyscallPostProcessor`]
    /// which deals with processing of system calls.
    pub fn from_alt_syscall(
        ktrap_frame: KTRAP_FRAME,
    ) {

        //
        // We want to match here on the SSN, and process each SSN as appropriate for 
        // our hooking needs.
        //
        let rax = ktrap_frame.Rax as u32;

        let syscall_data: Option<Syscall> = match rax {
            SSN_NT_ALLOCATE_VIRTUAL_MEMORY => Self::nt_allocate_vm(ktrap_frame),
            SSN_NT_OPEN_PROCESS => Self::nt_open_process(ktrap_frame),
            SSN_NT_WRITE_VM => Self::nt_write_vm(ktrap_frame),
            _ => {
                println!("[-] [sanctum] Unknown SSN received, {:?}", ktrap_frame.Rax as u32);
                None
            }
        };

        // Push the data onto the queue for processing
        if let Some(syscall_data) = syscall_data {
            SyscallPostProcessor::push(syscall_data);
        }
    }

    fn nt_write_vm(
        ktrap_frame: KTRAP_FRAME,
    ) -> Option<Syscall> {

        let current_pid = unsafe { PsGetCurrentProcessId() } as u32;


         None
    }

    fn nt_open_process(
        ktrap_frame: KTRAP_FRAME,
    ) -> Option<Syscall> {
        
        let client_id: CLIENT_ID = unsafe { 
            *(ktrap_frame.R9 as *const CLIENT_ID)
        };

        let remote_pid = client_id.UniqueProcess as u32;
        let current_pid = unsafe { PsGetCurrentProcessId() } as u32;

        // Currently only interested in foreign process handles
        if remote_pid == current_pid {
            return None;
        }

        let access_mask = ktrap_frame.Rdx as u32;
        
        Some(
            Syscall::from_kernel(
                current_pid, 
                NtFunction::NtOpenProcess(
                    NtOpenProcessData {
                        target_pid: remote_pid,
                        desired_mask: access_mask,
                    }
                )
            )
        )
    }

    fn nt_allocate_vm(
        ktrap_frame: KTRAP_FRAME,
    ) -> Option<Syscall> {
        let proc_handle = ktrap_frame.Rcx as HANDLE;

        let current_pid = unsafe { PsGetCurrentProcessId() } as u32;
        let dest_pid = handle_to_pid(proc_handle);

        // for now we only care about remote memory allocations
        if current_pid == dest_pid {
            return None;
        }

        let base_address = ktrap_frame.Rdx as *const c_void;
        let sz = ktrap_frame.R9 as usize;

        let stack_args = unsafe { ktrap_get_stack_args(&ktrap_frame, 2) };
        // SAFETY: These are copy, so suitable for directly inserting into the struct to keep around
        let alloc_type = stack_args[0] as u32;
        let protect_flags = stack_args[1] as u32;
        
        let syscall_data = Syscall::from_kernel(
            current_pid, 
            NtFunction::NtAllocateVirtualMemory(
                NtAllocateVirtualMemoryData {
                    dest_pid,
                    base_address: base_address as usize,
                    sz,
                    alloc_type,
                    protect_flags,
                }
            )
        );

        println!("Sd: {syscall_data:?}");

        Some(syscall_data)
    }
}

pub struct SyscallPostProcessor;

impl SyscallPostProcessor {
    /// Creates a new instance of the [`SyscallPostProcessor`], initialising internal state and spawning a
    /// worker system thread to do the work.
    ///
    /// # Returns
    /// - `Ok`
    /// - `Err` - variants:
    ///     - `ResourceStateInvalid`
    ///     - `MutexError`
    pub fn spawn() -> Result<(), DriverError> {
        if SYSCALL_PP_ACTIVE.load(Ordering::SeqCst) == true {
            println!("[sanctum] [-] Tried starting SyscallPostProcessor, but was already active.");
            return Err(DriverError::ResourceStateInvalid);
        }

        // Initialise the main queue which requires mutex protection
        match Grt::register_fast_mutex_checked(
            "alt_syscall_event_queue",
            VecDeque::<KernelSyscallIntercept>::new(),
        ) {
            Ok(_) => (),
            Err(e) => {
                println!("[sanctum] [-] Could not create queue FastMutex. {:?}", e);
                return Err(DriverError::MutexError);
            }
        };

        create_worker_thread()?;

        SYSCALL_PP_ACTIVE.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Pushes a [`KernelSyscallIntercept`] item onto the current queue for processing. This
    /// is the primary method of offloading system call data as to not block the main syscall
    /// dispatcher.
    pub fn push(syscall: Syscall) {
        if SYSCALL_PP_ACTIVE.load(Ordering::SeqCst) == false {
            return;
        }

        let syscall_data = KernelSyscallIntercept { syscall };

        let mut lock: FastMutexGuard<VecDeque<KernelSyscallIntercept>> =
            match Grt::get_fast_mutex("alt_syscall_event_queue") {
                Ok(lock) => match lock.lock() {
                    Ok(lock) => lock,
                    Err(e) => {
                        println!(
                            "[sanctum] [-] Could not lock alt_syscall_event_queue. {:?}",
                            e
                        );
                        return;
                    }
                },
                Err(e) => {
                    println!(
                        "[sanctum] [-] Could not lock get FM: alt_syscall_event_queue. {:?}",
                        e
                    );
                    return;
                }
            };

        lock.push_back(syscall_data);
    }

    /// Stops the worker thread, draining the queues and drops the mutex's.
    pub fn exit() -> Result<(), DriverError> {
        if SYSCALL_PP_ACTIVE.load(Ordering::SeqCst) == false {
            println!("[sanctum] [-] Tried exiting SyscallPostProcessor, but was already inactive.");
            return Err(DriverError::ResourceStateInvalid);
        }

        //
        // To ensure a clean termination, set the cancel flag to true, this will instruct the worker thread to terminate.
        // We then block until the thread has cleaned up before continuing, ensuring we don't get a BSOD.
        //
        SYSCALL_CANCEL_THREAD.store(true, Ordering::SeqCst);

        let thread_handle = SYSCALL_THREAD_HANDLE.load(Ordering::SeqCst);
        if thread_handle.is_null() {
            println!("[sanctum] [-] SYSCALL_THREAD_HANDLE was null. Cannot clean up resources.");
            return Err(DriverError::ResourceStateInvalid);
        }

        if !thread_handle.is_null() {
            let status = unsafe {
                KeWaitForSingleObject(
                    thread_handle,
                    Executive,
                    KernelMode as _,
                    FALSE as _,
                    null_mut(),
                )
            };

            if status != STATUS_SUCCESS {
                println!(
                    "[sanctum] [-] Did not successfully call KeWaitForSingleObject when trying to exit system thread for Alt Syscall monitoring."
                );
            }
            let _ = unsafe { ObfDereferenceObject(thread_handle) };
        }

        Ok(())
    }
}

/// Create a worker thread for the Alt Syscall post processing routine
fn create_worker_thread() -> Result<(), DriverError> {
    let mut thread_handle: HANDLE = null_mut();

    let thread_status = unsafe {
        PsCreateSystemThread(
            &mut thread_handle,
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            Some(syscall_post_processing_worker),
            null_mut(),
        )
    };

    if !nt_success(thread_status) {
        return Err(DriverError::Unknown(
            "Could not create new thread for post processing syscall events".to_string(),
        ));
    }

    // To prevent a BSOD when exiting the thread on driver unload, we need to reference count the handle
    // so that it isn't deallocated whilst waiting on the thread to exit.
    let mut object: *mut c_void = null_mut();
    if unsafe {
        ObReferenceObjectByHandle(
            thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            KernelMode as _,
            &mut object,
            null_mut(),
        )
    } != STATUS_SUCCESS
    {
        // If we had an error, we need to signal the thread to stop.
        SYSCALL_CANCEL_THREAD.store(true, Ordering::SeqCst);
        return Err(DriverError::Unknown(
            "Could not get thread handle by ObRef.. Alt syscalls not being monitored".to_string(),
        ));
    };

    SYSCALL_THREAD_HANDLE.store(object, Ordering::SeqCst);

    Ok(())
}

/// The worker thread routine which processes each syscall waiting in the queue.
///
/// This function is designed to be as ergonomic as possible, reducing lock contention as far as we can by using a
/// [`core::mem::take`] to drain the queue which is held by a lock that syscalls need to push to.
unsafe extern "C" fn syscall_post_processing_worker(_: *mut c_void) {
    let delay_as_duration = Duration::from_millis(100);
    let mut thread_sleep_time = LARGE_INTEGER {
        QuadPart: -((delay_as_duration.as_nanos() / 100) as i64),
    };

    loop {
        if SYSCALL_CANCEL_THREAD.load(Ordering::SeqCst) == true {
            break;
        }

        let _ =
            unsafe { KeDelayExecutionThread(KernelMode as _, FALSE as _, &mut thread_sleep_time) };

        let worker_queue = match extract_queued_items() {
            Some(w) => w,
            None => continue,
        };

        //
        // Process each syscall we intercepted, at the minimum this should add to the Ghost
        // Hunt where appropriate to detect Hells Gate / direct / indirect syscall abuse!
        // In addition to this, we can block certain syscalls until we meet a certain predicate,
        // for example, refusing to start a new thread in a foreign process until we validate some 
        // risk factors on the injecting process / target process, are there any Ghost Hunting timers 
        // outstanding for syscalls we care about.
        // 
        for syscall_data in worker_queue {
            ProcessMonitor::ghost_hunt_add_event(syscall_data.syscall);
        }
    }

    let _ = unsafe { PsTerminateSystemThread(STATUS_SUCCESS) };
    SYSCALL_CANCEL_THREAD.store(false, Ordering::SeqCst);
    SYSCALL_PP_ACTIVE.store(false, Ordering::SeqCst);
}

/// Drain the active queue into the worker queue, so we can start doing work on it without
/// causing contention of the queue that will be being pushed to with heavy load.
fn extract_queued_items() -> Option<VecDeque<KernelSyscallIntercept>>{
    let mut lock: FastMutexGuard<VecDeque<KernelSyscallIntercept>> =
        match Grt::get_fast_mutex("alt_syscall_event_queue") {
            Ok(lock) => match lock.lock() {
                Ok(lock) => lock,
                Err(e) => {
                    println!(
                        "[sanctum] [-] Could not lock alt_syscall_event_queue. {:?}",
                        e
                    );
                    return None;
                }
            },
            Err(e) => {
                println!(
                    "[sanctum] [-] Could not lock get FM: alt_syscall_event_queue. {:?}",
                    e
                );
                return None;
            }
    };

    if lock.is_empty() {
        return None;
    }

    Some(mem::take(&mut *lock))
}