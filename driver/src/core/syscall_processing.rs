//! This module relates to the post-processing of system call's intercepted via the Alternate Syscalls technique.

use core::{
    ffi::c_void,
    mem,
    ptr::null_mut,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
    time::Duration,
};

use alloc::{collections::vec_deque::VecDeque, string::ToString};
use wdk::{nt_success, println};
use wdk_mutex::{
    fast_mutex::{FastMutex, FastMutexGuard},
    grt::Grt,
};
use wdk_sys::{
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
    FALSE, HANDLE, LARGE_INTEGER, PIO_WORKITEM, PVOID, STATUS_SUCCESS, THREAD_ALL_ACCESS,
    ntddk::{
        IoFreeWorkItem, KeDelayExecutionThread, KeWaitForSingleObject, ObReferenceObjectByHandle,
        ObfDereferenceObject, PsCreateSystemThread, PsTerminateSystemThread,
    },
};

use crate::utils::DriverError;

/// Indicates whether the [`SyscallPostProcessor`] system is active or not. Active == true.
/// Using a static atomic as we cannot explicitly get a handle to a SyscallPostProcessor if it does not
/// exist, so checking will be hard. This static is internal to this module.
static SYSCALL_PP_ACTIVE: AtomicBool = AtomicBool::new(false);
/// A flag which condition is checked to determine whether the thread is running or not. Setting this to false
/// allows the thread to terminate itself.
static SYSCALL_CANCEL_THREAD: AtomicBool = AtomicBool::new(false);
static SYSCALL_THREAD_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

pub struct NtAllocateVirtualMemory {
    pub dest_pid: u32,
    pub base_address: *const c_void,
    pub sz: usize,
    pub alloc_type: u32,
    pub protect_flags: u32,
}

pub struct NtOpenProcess {
    target_pid: u32,
}

pub enum Syscall {
    NtOpenProcess(NtOpenProcess),
    NtAllocateVirtualMemory(NtAllocateVirtualMemory),
}

pub struct KernelSyscallIntercept {
    pub pid: u64,
    pub syscall: Syscall,
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

    pub fn push(syscall_data: KernelSyscallIntercept) {
        if SYSCALL_PP_ACTIVE.load(Ordering::SeqCst) == false {
            return;
        }

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

        //
        // Drain the active queue into the worker queue, so we can start doing work on it without
        // causing contention of the queue that will be being pushed to with heavy load.
        // We can drain the queue within a new scope so RAII releases the mutex so syscalls can start operating
        // again. This section needs to be QUICK.
        //
        let worker_queue = {
            let mut lock: FastMutexGuard<VecDeque<KernelSyscallIntercept>> =
                match Grt::get_fast_mutex("alt_syscall_event_queue") {
                    Ok(lock) => match lock.lock() {
                        Ok(lock) => lock,
                        Err(e) => {
                            println!(
                                "[sanctum] [-] Could not lock alt_syscall_event_queue. {:?}",
                                e
                            );
                            continue;
                        }
                    },
                    Err(e) => {
                        println!(
                            "[sanctum] [-] Could not lock get FM: alt_syscall_event_queue. {:?}",
                            e
                        );
                        continue;
                    }
                };

            if lock.is_empty() {
                continue;
            }

            // This will take ownership of the data held by the lock, whilst clearing the VecDeq back to its
            // original Default value.
            mem::take(&mut *lock)
        };

        println!("[sanctum] [THREAD] Worker queue sz {}", worker_queue.len());

        // Processing this will be the entry into Ghost Hunting now for syscalls.
        for syscall in worker_queue {
            // todo
        }

        let _ =
            unsafe { KeDelayExecutionThread(KernelMode as _, FALSE as _, &mut thread_sleep_time) };
    }

    let _ = unsafe { PsTerminateSystemThread(STATUS_SUCCESS) };
    SYSCALL_CANCEL_THREAD.store(false, Ordering::SeqCst);
    SYSCALL_PP_ACTIVE.store(false, Ordering::SeqCst);
}
