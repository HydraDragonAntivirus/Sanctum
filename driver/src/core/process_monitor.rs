//! # Sanctum Process Monitor
//!
//! The `process_monitor` module implements a Windows-kernel driver component
//! that tracks process lifecycles and applies “ghost-hunting” heuristics to detect
//! syscall-hooking evasion.  
//!
//! For more info on GhostHunting, see my blog post:
//! https://fluxsec.red/edr-syscall-hooking
//!
//! Key features:
//! - Maintains a global map of `Process` metadata  
//! - Spawns a monitoring thread to time syscall events  
//! - Exposes APIs to register new processes, remove exited ones, and feed
//!   Ghost Hunting telemetry

use core::{
    ffi::c_void,
    ptr::{null, null_mut},
    time::Duration,
};

use alloc::{
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use shared_no_std::{
    driver_ipc::ProcessStarted,
    ghost_hunting::{NtFunction, Syscall, SyscallEventSource},
};
use wdk::{nt_success, println};
use wdk_mutex::{
    errors::GrtError,
    fast_mutex::{FastMutex, FastMutexGuard},
    grt::Grt,
};
use wdk_sys::{
    _EPROCESS,
    _MODE::KernelMode,
    HANDLE, LARGE_INTEGER, LIST_ENTRY, PROCESS_ALL_ACCESS, PROCESS_BASIC_INFORMATION,
    PsProcessType, STATUS_SUCCESS, THREAD_ALL_ACCESS, TRUE,
    ntddk::{
        IoGetCurrentProcess, KeDelayExecutionThread, KeQuerySystemTimePrecise,
        ObOpenObjectByPointer, ObReferenceObjectByHandle, PsCreateSystemThread, PsGetProcessId,
    },
};

use crate::{
    ffi::{InitializeObjectAttributes, NtQueryInformationProcess},
    utils::{DriverError, eprocess_to_process_name},
};

use super::syscall_processing::SyscallPostProcessor;

/// A `Process` is a Sanctum driver representation of a Windows process so that actions it preforms, and is performed
/// onto it, can be tracked and monitored.
pub struct Process {
    pub pid: u32,
    /// Parent pid
    pub ppid: u32,
    pub process_image: String,
    pub commandline_args: String,
    pub risk_score: u16,
    pub allow_listed: bool, // whether the application is allowed to exist without monitoring
    /// Creates a time window in which a process handle must match from a hooked syscall with
    /// the kernel receiving the notification. Failure to match this may be an indicator of hooked syscall evasion.
    pub ghost_hunting_timers: Vec<GhostHuntingTimer>,
    targeted_by_apis: Vec<ProcessTargetedApis>,
}

// todo needs implementing
#[derive(Debug, Default)]
pub struct ProcessTargetedApis {}

/// A `GhostHuntingTimer` is the timer metadata associated with the Ghost Hunting technique on my blog:
/// https://fluxsec.red/edr-syscall-hooking
///
/// The data contained in this struct allows timers to be polled and detects abuse of direct syscalls / hells gate.
pub struct GhostHuntingTimer {
    // Query the time via `KeQuerySystemTime`
    pub timer_start: LARGE_INTEGER,
    pub event_type: NtFunction,
    /// todo update docs
    pub origin: SyscallEventSource,
    /// Specifies which syscall types of a matching event this is cancellable by. As the EDR monitors multiple
    /// sources of telemetry, we cannot do a 1:1 cancellation process.
    pub cancellable_by: isize,
}

/// The ProcessMonitor is responsible for monitoring all processes running; this
/// structure holds a hashmap of all processes by the pid as an integer, and
/// the data within is a MonitoredProcess containing the details
///
/// The key of processes hashmap is the pid, which is duplicated inside the Process
/// struct.
pub struct ProcessMonitor;

#[derive(Debug)]
pub enum ProcessErrors {
    PidNotFound,
    DuplicatePid,
    BadHandle,
    BadFnAddress,
    BaseAddressNull,
    FailedToWriteMemory,
    FailedToCreateRemoteThread,
    FailedToOpenProcess,
}

impl ProcessMonitor {
    /// Instantiates a new `ProcessMonitor`; which is just an interface for access to the underlying
    /// globally managed mutex via `Grt` (my `wdk-mutex` crate).
    ///
    /// This function should only be called once on driver initialisation.
    ///
    /// The `ProcessMonitor` is required for use in driver callback routines, therefore we can either track via a single
    /// static; or use the `Grt` design pattern (favoured in this case).
    pub fn new() -> Result<(), GrtError> {
        // Walk all processes and add to the proc mon.
        let mut processes = BTreeMap::<u32, Process>::new();
        walk_processes_get_details(&mut processes);

        println!("[sanctum] [i] Process monitor discovered {} processes on start.", processes.len());

        Grt::register_fast_mutex("ProcessMonitor", processes)
    }

    pub fn onboard_new_process(process: &ProcessStarted) -> Result<(), ProcessErrors> {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if process_lock.get(&process.pid).is_some() {
            return Err(ProcessErrors::DuplicatePid);
        }

        // todo this actually needs filling out with the relevant data
        process_lock.insert(process.pid, Process {
            pid: process.pid,
            ppid: process.parent_pid,
            process_image: process.image_name.clone(),
            commandline_args: process.command_line.clone(),
            risk_score: 0,
            allow_listed: false,
            ghost_hunting_timers: Vec::new(),
            targeted_by_apis: Vec::new(),
        });

        Ok(())
    }

    // todo need to remove processes from the monitor once they are terminated
    pub fn remove_process(pid: u32) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();
        process_lock.remove(&pid);
    }

    /// Notifies the Ghost Hunting management that a new huntable event has occurred.
    pub fn ghost_hunt_add_event(pid: u32, signal: Syscall) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if let Some(process) = process_lock.get_mut(&pid) {
            let mut current_time = LARGE_INTEGER::default();
            unsafe { KeQuerySystemTimePrecise(&mut current_time) };

            process.add_ghost_hunt_timer(GhostHuntingTimer {
                timer_start: current_time,
                cancellable_by: 1,
                event_type: signal.data,
                origin: signal.source,
            });
        }
    }

    /// This function is responsible for polling all Ghost Hunting timers to try match up hooked syscall API calls
    /// with kernel events sent from our driver.
    ///
    /// This is part of my Ghost Hunting technique https://fluxsec.red/edr-syscall-hooking
    pub fn poll_ghost_timers() {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        for (_, process) in process_lock.iter_mut() {
            if process.ghost_hunting_timers.is_empty() {
                continue;
            }

            //
            // In here process each API event we are tracking in the ghost timers.
            //

            // todo try integrate the following into the windows-drivers-rs project:
            // https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/using-timers
            // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdftimer/nf-wdftimer-wdftimercreate
            // Kinda wanna do it as a driver POC for now, then once working, can try migrate it into the windows drivers
            // project so I can use event timers from the wdk, rather than a system thread.

            // todo these are being computed every time; perhaps they could be moved inside of the `FastMutex` and computed
            // only once
            let max_time_allowed = Duration::from_secs(1);
            let max_time_allowed = LARGE_INTEGER {
                QuadPart: ((max_time_allowed.as_nanos() / 100) as i64),
            };

            let mut index: usize = 0; // index of iterator over the ghost timers
            for item in &process.ghost_hunting_timers {
                let mut current_time = LARGE_INTEGER::default();
                unsafe { KeQuerySystemTimePrecise(&mut current_time) };

                // We are only running the driver on x64, so we can compute the delta using the QuadPart.

                let time_delta = unsafe { current_time.QuadPart - item.timer_start.QuadPart };

                if time_delta > unsafe { max_time_allowed.QuadPart } {
                    // process.update_process_risk_score(item.weight);
                    println!(
                        "[sanctum] *** TIMER EXCEEDED on: {:?}, pid responsible: {}",
                        item.event_type, process.pid
                    );

                    process.ghost_hunting_timers.remove(index);
                    break;
                }

                index += 1;
            }
        }
    }

    pub fn handle_syscall_ghost_hunt_event(data: &Syscall) {
        // println!("[sanctum] [i] Syscall ghost hunt data: {:?}", data);
        ProcessMonitor::ghost_hunt_add_event(data.pid, data.clone());
    }

    fn get_mtx_inner<'a>() -> FastMutexGuard<'a, BTreeMap<u32, Process>> {
        // todo rather than panic, ? error
        let process_lock: FastMutexGuard<BTreeMap<u32, Process>> =
            match Grt::get_fast_mutex("ProcessMonitor") {
                Ok(mtx) => match mtx.lock() {
                    Ok(l) => l,
                    Err(e) => {
                        println!(
                            "[-] Error locking KMutex for new process. Panicking. {:?}",
                            e
                        );
                        panic!()
                    }
                },
                Err(e) => {
                    println!("[sanctum] [-] Could not lock fast mutex. {:?}", e);
                    panic!()
                }
            };

        process_lock
    }

    /// Spawns a system thread to poll Ghost Hunting timers.
    ///
    /// # Panics
    /// Panics if thread creation or handle reference fails.
    pub fn start_ghost_hunt_monitor() {
        // Start the thread that will monitor for changes
        let mut thread_handle: HANDLE = null_mut();

        let thread_status = unsafe {
            PsCreateSystemThread(
                &mut thread_handle,
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                Some(thread_run_monitor_ghost_hunting),
                null_mut(),
            )
        };

        if thread_status != STATUS_SUCCESS {
            println!(
                "[sanctum] [-] Could not create new thread for monitoring ETW patching, kernel ETW is not being monitored."
            );
            panic!();
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
            println!(
                "[sanctum] [-] Could not get thread handle by ObRef.. kernel ETW is not being monitored."
            );
            panic!()
        }

        if Grt::register_fast_mutex("TERMINATION_FLAG_GH_MONITOR", false).is_err() {
            println!(
                "[sanctum] [-] Could not register TERMINATION_FLAG_GH_MONITOR as a FAST_MUTEX, PANICKING."
            );
            panic!()
        }
        if Grt::register_fast_mutex("GH_THREAD_HANDLE", object).is_err() {
            println!(
                "[sanctum] [-] Could not register GH_THREAD_HANDLE as a FAST_MUTEX, PANICKING"
            );
            panic!()
        }
    }
}

/// Remove an event source from a given Ghost Hunting timer.
///
/// This function will modify the timer object to remove a cancellable event origin in place.
///
/// # Args
/// - `timer`: A mutable reference to the GhostHuntingTimer for a given process
/// - `new_source`: An isize representing whether we need to unset a different bit (see remarks)
///
/// # Remarks
/// In the case where you are unsetting the cancellable bit for the 'self' i.e. there are no active Ghost Hunting
/// events in the queue for that API, you want to unset the bit for where it came from, as you only want to match on the
/// other bit fields. In this case, enter this `new_source` param as `None`.
///
/// However; if you are processing a **new** API where there **is** an active timer waiting for the relevant cancellation events
/// to come in, then opt for `Some` where the `T` is an `SyscallEventSource` representing the source of where the syscall
/// was detected from.
#[inline(always)]
fn unset_event_flag_in_timer(
    timer: &mut GhostHuntingTimer,
    new_source: Option<SyscallEventSource>,
) {
    // flip the set bit back to a 0
    match new_source {
        Some(new_source) => {
            timer.cancellable_by = timer.cancellable_by as isize ^ new_source as isize;
        }
        None => timer.cancellable_by = timer.cancellable_by as isize ^ timer.origin as isize,
    }
}

impl Process {
    /// Adds a ghost hunt timer specifically to a process.
    ///
    /// This function will internally deal with cases where a timer for the same API already exists. If the timer already exists, it will
    /// use bit flags to
    fn add_ghost_hunt_timer(&mut self, mut new_timer: GhostHuntingTimer) {
        // If the timers are empty; then its the first in so we can add it to the list straight up.
        if self.ghost_hunting_timers.is_empty() {
            // remove the current notification from the cancellable by (prevent dangling timers)
            unset_event_flag_in_timer(&mut new_timer, None);
            self.ghost_hunting_timers.push(new_timer);
            return;
        }

        // Otherwise, there is data in the ghost hunting timers ...
        for (index, timer_iter) in self.ghost_hunting_timers.iter_mut().enumerate() {
            // If the API Origin that this fn relates to is found in the list of cancellable APIs then cancel them out.
            // Part of the core Ghost Hunting logic. First though we need to check that the event type that can cancel it out
            // is present in the active flags (bugs were happening where other events of the same type were being XOR'ed, so if they
            // were previously unset, the flag  was being reset and the process was therefore failing).
            // To get around this we do a bitwise& check before running the XOR in unset_event_flag_in_timer.
            if core::mem::discriminant(&timer_iter.event_type)
                == core::mem::discriminant(&new_timer.event_type)
            {
                if timer_iter.cancellable_by & new_timer.origin as isize
                    == new_timer.origin as isize
                {
                    unset_event_flag_in_timer(timer_iter, Some(new_timer.origin));

                    // If everything is cancelled out (aka all bit fields set to 0 remove the timer completely from the process)
                    if timer_iter.cancellable_by == 0 {
                        self.ghost_hunting_timers.remove(index);
                        return;
                    }

                    return;
                }
            }
        }

        // we did not match on the above timer.event_type in the list of active timers, so add the element as a new timer
        // remove the current notification from the cancellable by (prevent dangling timers)
        unset_event_flag_in_timer(&mut new_timer, None);
        self.ghost_hunting_timers.push(new_timer);
    }
}

/// Worker thread entry point. Sleeps once per second, polls all `ghost_hunting_timers`, and exits when the driver is unloaded.
unsafe extern "C" fn thread_run_monitor_ghost_hunting(_: *mut c_void) {
    let delay_as_duration = Duration::from_secs(1);
    let mut thread_sleep_time = LARGE_INTEGER {
        QuadPart: -((delay_as_duration.as_nanos() / 100) as i64),
    };

    loop {
        let _ =
            unsafe { KeDelayExecutionThread(KernelMode as _, TRUE as _, &mut thread_sleep_time) };
        ProcessMonitor::poll_ghost_timers();

        // Check if we have received the cancellation flag, without this check we will get a BSOD. This flag will be
        // set to true on DriverExit.
        let terminate_flag_lock: &FastMutex<bool> = match Grt::get_fast_mutex(
            "TERMINATION_FLAG_GH_MONITOR",
        ) {
            Ok(lock) => lock,
            Err(e) => {
                // Maybe this should terminate the thread instead? This would be a bad error to have as it means we cannot.
                // instruct the thread to terminate cleanly on driver exit. Or maybe do a count with max tries? We shall see.
                println!(
                    "[sanctum] [-] Error getting fast mutex for TERMINATION_FLAG_GH_MONITOR. {:?}",
                    e
                );
                continue;
            }
        };
        let lock = match terminate_flag_lock.lock() {
            Ok(lock) => lock,
            Err(e) => {
                println!(
                    "[sanctum] [-] Failed to lock mutex for terminate_flag_lock/ {:?}",
                    e
                );
                continue;
            }
        };
        if *lock {
            break;
        }
    }
}

/// Walk all processes and get [`Process`] details for each process running on the system.
///
/// This function is designed to be run on driver initialisation / setup to record what processes are running at the starting point.
/// It may be possible, during the snapshot, a new process is started and is missed.
fn walk_processes_get_details(processes: &mut BTreeMap<u32, Process>) {
    // Offsets in bytes for Win11 24H2
    const ACTIVE_PROCESS_LINKS_OFFSET: usize = 0x1d8;

    let current_process = unsafe { IoGetCurrentProcess() };
    if current_process.is_null() {
        println!("[sanctum] [-] current_process was NULL");
        return;
    }

    // Get the starting head for the list
    let head =
        unsafe { (current_process as *mut u8).add(ACTIVE_PROCESS_LINKS_OFFSET) } as *mut LIST_ENTRY;
    let mut entry = unsafe { (*head).Flink };

    while entry != head {
        // Get the record for the _EPROCESS
        let p_e_process =
            unsafe { (entry as *mut u8).sub(ACTIVE_PROCESS_LINKS_OFFSET) } as *mut _EPROCESS;

        let pid = unsafe { PsGetProcessId(p_e_process as *mut _) } as usize;

        // We can't get a handle / process details for the System Idle Process
        if pid == 0 {
            entry = unsafe { (*entry).Flink };
            continue;
        }

        // Pull out the process details we need to add to our process list
        let process_details = match extract_process_details(p_e_process, pid) {
            Ok(p) => p,
            Err(e) => {
                println!(
                    "[sanctum] [-] Failed to get process data during process walk. {:?}",
                    e
                );
                entry = unsafe { (*entry).Flink };
                continue;
            }
        };

        let pid = process_details.pid;
        let img = process_details.process_image.clone();
        if processes
            .insert(process_details.pid, process_details)
            .is_some()
        {
            println!(
                "[sanctum] [-] Duplicate pid found whilst walking processes? pid: {}, image: {}",
                pid, img
            );
        }

        entry = unsafe { (*entry).Flink };
    }
}

/// Extracts process details from a given `_EPROCESS`. It collates:
///
/// - pid
/// - parent pid
/// - image name (not full path)
fn extract_process_details<'a>(process: *mut _EPROCESS, pid: usize) -> Result<Process, DriverError> {
    let process_name = eprocess_to_process_name(process as *mut _)?;
    let mut out_sz = 0;

    let mut process_information = PROCESS_BASIC_INFORMATION::default();
    let mut process_handle: HANDLE = null_mut();

    let result = unsafe {
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

    if !nt_success(result) {
        println!(
            "[sanctum] [-] ObOpenObjectByPointer failed during process walk for pid: {pid}. Error: {:#x}",
            result
        );
        return Err(DriverError::Unknown(
            "Could not open process handle".to_string(),
        ));
    }

    let result = unsafe {
        NtQueryInformationProcess(
            process_handle,
            0,
            &mut process_information as *mut _ as *mut _,
            size_of_val(&process_information) as _,
            &mut out_sz,
        )
    };

    if !nt_success(result) {
        println!(
            "[sanctum] [-] Result of NtQueryInformationProcess was bad. Code: {:#x}. Out sz: {}",
            result, out_sz
        );
        return Err(DriverError::Unknown(
            "Could not query process information".to_string(),
        ));
    }

    let ppid = process_information.InheritedFromUniqueProcessId as u32;

    Ok(Process {
        pid: pid as _,
        ppid,
        process_image: process_name.to_string(),
        commandline_args: String::new(),
        risk_score: 0,
        allow_listed: false,
        ghost_hunting_timers: Vec::new(),
        targeted_by_apis: Vec::new(),
    })
}
