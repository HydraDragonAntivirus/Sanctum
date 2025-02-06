use std::{collections::HashMap, ffi::{c_void, CStr}, time::{Duration, SystemTime}};

use shared_no_std::{constants::SANCTUM_DLL_RELATIVE_PATH, driver_ipc::ProcessStarted};
use shared_std::processes::{ApiOrigin, GhostHuntingTimers, Process, EventTypeWeighted, VirtualAllocExEtw, VirtualAllocExSyscall};
use windows::{core::{s, PSTR}, Win32::{Foundation::{CloseHandle, GetLastError, MAX_PATH}, System::{Diagnostics::{Debug::WriteProcessMemory, ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPALL}}, LibraryLoader::{GetModuleHandleA, GetProcAddress}, Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE}, Threading::{CreateRemoteThread, GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameA, PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE}}}};

use crate::utils::{env::get_logged_in_username, log::{Log, LogLevel}};

/// The max wait time from events coming from an injected Sanctum DLL & from the driver hooks
const MAX_WAIT: Duration = Duration::from_millis(600);
/// The ETW max wait time needs extending, as this takes a little longer to come through
const MAX_WAIT_ETW: Duration = Duration::from_millis(2300); // 3 seconds - this is quite long, but alas

// Allow an impl block in this module, as opposed to implementing it outside of here; seeing as the impl is likely not required outside the 
// engine. If it needs to be, then the impl will be moved to the shared crate.
pub trait ProcessImpl {
    fn update_process_risk_score(&mut self, score: EventTypeWeighted);
    fn add_ghost_hunt_timer(&mut self, syscall_origin: ApiOrigin, event_type: EventTypeWeighted);
}

/// A trait to allow us to specify the implementation in this crate as opposed to in the shared crate; it makes more logical sense to have this 
/// implemented in the current crate.
pub trait SyscalLTypeImpl {
    fn cancellable_by(syscall_type: &EventTypeWeighted) -> Vec<ApiOrigin>;
}

impl SyscalLTypeImpl for EventTypeWeighted {
    /// Determine what events can cancel a given syscall type.
    /// 
    /// # Args
    /// The function accepts a reference to the syscall type you are wanting to query information on.
    /// 
    /// # Returns
    /// Will return a vector of [`ApiOrigin`] which gives situational information on how **many** events to expect
    /// as well as the exact Sanctum API's which will be able to cancel out the Ghost Hunt timers.
    fn cancellable_by(syscall_type: &EventTypeWeighted) -> Vec<ApiOrigin> {
        let mut origins: Vec<ApiOrigin> = vec![];

        match syscall_type {
            EventTypeWeighted::OpenProcess => {
                origins.push(ApiOrigin::Kernel);
                origins.push(ApiOrigin::SyscallHook);
            },
            EventTypeWeighted::VirtualAllocEx => {
                // origins.push(ApiOrigin::Kernel);
                origins.push(ApiOrigin::Etw);
                origins.push(ApiOrigin::SyscallHook);
            },
            EventTypeWeighted::CreateRemoteThread => {
                todo!()
            },
        }
    
        origins
    }
}

static IGNORED_PROCESSES: [&str; 4] = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\Taskmgr.exe",
    r"C:\Windows\System32\RuntimeBroker.exe",
    r"C:\Windows\explorer.exe",
];

static TARGET_EXE: &str = "malware";

/// The ProcessMonitor is responsible for monitoring all processes running; this 
/// structure holds a hashmap of all processes by the pid as an integer, and 
/// the data within is a MonitoredProcess containing the details
/// 
/// The key of processes hashmap is the pid, which is duplicated inside the Process
/// struct.
#[derive(Debug, Default)]
pub struct ProcessMonitor {
    processes: HashMap<u64, Process>,
    max_risk_score: u16,
}

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
    pub fn new() -> Self {
        ProcessMonitor {
            processes: HashMap::new(),
            // Define the max risk score a process is allowed to have before we start some interventions
            max_risk_score: 100,
        }
    }

    /// This function will complete the onboarding of a newly created process including:
    /// 
    /// todo 1) Process kernel information about the process (such as with the syscall detection logic)
    /// 
    /// todo 2) Grant permission for the process to be created / instruct the kernel to kill the process
    /// 
    /// 3) Inject the EDR DLL into the newly created process
    /// 4) Register the process with [`ProcessMonitor`]
    pub async fn onboard_new_process(&mut self, proc: &ProcessStarted) -> Result<(), ProcessErrors> {

        let logger = Log::new();

        // todo kernel stuff here for points 1 and 2
        /*
         */

        // Inject the EDR's DLL. 
        // TODO for now to prevent system instability this will only be done for Notepad. This will need to be 
        // reflected at some point for all processes.
        if proc.image_name.contains(TARGET_EXE) {
            println!("[i] Target process detected, injecting EDR DLL...");
            if let Err(e) = inject_edr_dll(proc.pid) {
                logger.log(LogLevel::Error, &format!("Error injecting DLL: {:?}", e));
            };
        }

        // The process can now be tracked, so register it with the ProcessMonitor
        self.register_process(proc).await?;

        Ok(())

    }

    /// Registers a process with the [`ProcessMonitor`] which will track the process. This should be used to add
    /// the process to the [`ProcessMonitor`] and shall not deal with any additional tasks, such as injection, or 
    /// other 'middleware' actions.
    async fn register_process(&mut self, proc: &ProcessStarted) -> Result<(), ProcessErrors> {
        //
        // First check we aren't inserting a duplicate PID, this may happen if we haven't received
        // a notification that a process has been terminated; or that we have a new process queued to
        // insert before a delete item which is queued.
        // todo this can be solved by first batch running deletes, before running updates.
        //

        let e = self.processes.get(&proc.pid);
        if e.is_some() {
            return Err(ProcessErrors::DuplicatePid);
        }

        // println!("Image name: {}", proc.image_name);

        let mut allow_listed = false;
        for item in IGNORED_PROCESSES {
            if proc.image_name.eq(item) {
                allow_listed = true;
                break;
            }
        }

        self.processes.insert(proc.pid, Process {
            pid: proc.pid,
            process_image: proc.image_name.clone(),
            commandline_args: proc.command_line.clone(),
            risk_score: 0,
            allow_listed,
            sanctum_protected_process: false,
            ghost_hunting_timers: Vec::new(),
        });

        Ok(())
    }

    pub async fn remove_process(&mut self, pid: u64) {
        self.processes.remove(&pid);
    }

    /// Extends the processes hashmap through the std extend function on the inner processes hashmap
    pub fn extend_processes(&mut self, foreign_hashmap: ProcessMonitor) {
        self.processes.extend(foreign_hashmap.processes);

        let logger = Log::new();
        logger.log(crate::utils::log::LogLevel::Info, &format!("Discovered {} running processes on startup.", self.processes.len()));
    }


    /// Query a given process by its Pid, returning information about the process
    pub fn query_process_by_pid(&self, pid: u64) -> Option<Process> {
        if let Some(process) = self.processes.get(&pid) {
            return Some(process.clone());
        } else {
            return None;
        }
    }


    /// Process a new process handle being obtained from a callback in the driver.
    pub fn add_handle_driver_notified(&mut self, pid: u64, target: u64, granted: u32, requested: u32) {
        // If the process is allowed to do as it pleases, then discard early.
        if let Some(process) = self.processes.get(&pid) {
            if process.allow_listed == true || !process.process_image.contains(TARGET_EXE) {
                return;
            }
        }

        if pid == target {
            return;
        }

        // If the source is our engine
        if pid == unsafe {GetCurrentProcessId() as u64} {
            return;
        }

        let log = Log::new();


        //
        // Do some basic error checking before adding data
        //

        // if the list of processes doesn't contain the PID
        if !self.processes.contains_key(&pid) {
            // todo this happens a lot - why? Could this be because the source terminates before
            // this runs? 
            // todo look at a timing issue with the driver - do we still want to create the process here?
            // 
            // log.log(
            //     crate::utils::log::LogLevel::Error, 
            //     &format!("Source pid: {pid} not found when trying to process a handle request.")
            // );

            return;
        }

        self.ghost_hunt_open_process_add(pid, ApiOrigin::Kernel);


        // TODO: the below logic isn't quite right - it turns out after some experimentation assigning risk scores to 
        // handles is not a good measure of intent; tracking handles is still probably a good thing, however it begs the
        // question just disallowing `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory` etc is just better in 
        // every way without having to track process handles?
        return;

        //
        // Determine the mask.
        // Match on the granted HANDLE access rights mask for the case where it == PROCESS_ALL_ACCESS; we can assign
        // a hard fixed score. As the PROCESS_ALL_ACCESS will also be true for its sub matches, we need to distinguish
        // a request for all access from the sub masks.
        // For any other mask; we can then add cumulative risk scores per mask, which will still catch people trying to
        // evade the EDR by changing the  access from READ, to WRITE, to OPERATION, etc.
        //

        let mut risk_score_for_handle: u16 = 0;

        if granted & PROCESS_ALL_ACCESS.0 != 0 {
            println!("ALL ACCESS RIGHTS");
            risk_score_for_handle = 60;
        } else {

            //
            // Process the sub masks where there != match for PROCESS_ALL_ACCESS
            //
            if granted & PROCESS_CREATE_PROCESS.0 != 0 {
                println!("PROCESS_CREATE_PROCESS");
                risk_score_for_handle = 20;
            }
            if granted & PROCESS_CREATE_THREAD.0 != 0 {
                println!("PROCESS_CREATE_THREAD");
                risk_score_for_handle = 30;
            }
            if granted & PROCESS_DUP_HANDLE.0 != 0 {
                println!("PROCESS_DUP_HANDLE");
                risk_score_for_handle = 20;
            }
            if granted & PROCESS_QUERY_INFORMATION.0 != 0 {
                println!("PROCESS_QUERY_INFORMATION");
                risk_score_for_handle = 5;
            }
            if granted & PROCESS_QUERY_LIMITED_INFORMATION.0 != 0 {
                println!("PROCESS_QUERY_LIMITED_INFORMATION");
                risk_score_for_handle = 5;
            }
            if granted & PROCESS_SUSPEND_RESUME.0 != 0 {
                println!("PROCESS_SUSPEND_RESUME");
                risk_score_for_handle = 30;
            }
            if granted & PROCESS_TERMINATE.0 != 0 {
                println!("PROCESS_TERMINATE");
                risk_score_for_handle = 5;
            }
            if granted & PROCESS_VM_READ.0 != 0 {
                println!("PROCESS_VM_READ");
                risk_score_for_handle = 30;
            }
            if granted & PROCESS_VM_OPERATION.0 != 0 {
                println!("PROCESS_VM_OPERATION");
                risk_score_for_handle = 30;
            }
            if granted & PROCESS_VM_WRITE.0 != 0 {
                println!("PROCESS_VM_WRITE");
                risk_score_for_handle = 30;
            }

        }

        let p = self.processes.get_mut(&pid);
        if p.is_some() {
            p.unwrap().risk_score += risk_score_for_handle;
            let p = self.processes.get(&pid).unwrap();
            let t = self.processes.get(&target);
            println!("[i] Risk score for the process {pid} {}: {}. Accessing: {} {:?}", p.process_image, p.risk_score, target, t);
        }

    }


    /// This function is responsible for polling all Ghost Hunting timers to try match up hooked syscall API calls
    /// with kernel events sent from our driver.
    /// 
    /// This is part of my Ghost Hunting technique https://fluxsec.red/edr-syscall-hooking
    pub fn poll_ghost_timer(&mut self) {
        //
        // For each process we are tracking; determine if any timers are active from syscall stubs. If no timers are active then
        // we can simply ignore them. If they are active, then we should have received a driver notification matching the event
        // the syscall hooked within that time frame. If no such event is received; something untoward is going on, and as such,
        // elevate the risk score of the process.
        //
        
        for (_, process) in self.processes.iter_mut() {
            if process.ghost_hunting_timers.is_empty() {
                continue;
            }

            //
            // In here process each API event we are tracking in the ghost timers.
            //

            let mut index: usize = 0; // index of iterator over the ghost timers
            for item in &process.clone().ghost_hunting_timers {
                if let Ok(t) = item.timer.elapsed() {
                    if item.cancellable_by.contains(&ApiOrigin::Etw) {
                        if t > MAX_WAIT_ETW {
                            process.update_process_risk_score(item.event_type.clone());
                            process.ghost_hunting_timers.remove(index);
                            println!("******* RISK SCORE RAISED AS TIMER EXCEEDED on: {:?}", item.event_type);
                            break;
                        }
                    } else {
                        if t > MAX_WAIT {
                            process.update_process_risk_score(item.event_type.clone());
                            process.ghost_hunting_timers.remove(index);
                            println!("******* RISK SCORE RAISED AS TIMER EXCEEDED on: {:?}", item.event_type);
                            break;
                        }
                    }
                }

                index += 1;
            }
        }
    }

    /// The entry point for adding the message from an injected DLL that an ZwOpenProcess syscall was made
    pub fn ghost_hunt_open_process_add(&mut self, pid: u64, syscall_origin: ApiOrigin) {
        if let Some(process) = self.processes.get_mut(&pid) {
            process.add_ghost_hunt_timer(syscall_origin, EventTypeWeighted::OpenProcess);
        } else {
            // todo ok something very wrong if this gets called!!
            let log = Log::new();
            log.log(LogLevel::NearFatal, "Open Process from DLL request made that can not be found in active process list.");
        }
    }

    /// Handle a VirtualAllocEx signal being received from a remote process from the injected EDR DLL.
    pub fn ghost_hunt_virtual_alloc_ex_add_from_dll(&mut self, signal: VirtualAllocExSyscall) {
        let log = Log::new();
        let syscall_origin = ApiOrigin::SyscallHook;

        // select the process
        let pid = signal.pid as u64;
        let process = if let Some(p) = self.processes.get_mut(&pid) {
            p
        } else {
            log.log(LogLevel::Error, &format!("Could not find pid {pid} from ZwAllocateVirtualMemory signal from {:?}.", syscall_origin));
            return;
        };
        
        // todo determine different rwx permissions in the future once implemented.
        process.add_ghost_hunt_timer(syscall_origin, EventTypeWeighted::VirtualAllocEx);
    }

    /// Handle a VirtualAllocEx signal being received from a remote process.
    pub fn ghost_hunt_virtual_alloc_ex_add_from_etw(&mut self, signal: VirtualAllocExEtw) {
        let log = Log::new();
        let syscall_origin = ApiOrigin::Etw;

        // select the process
        let pid = signal.pid as u64;
        let process = if let Some(p) = self.processes.get_mut(&pid) {
            p
        } else {
            log.log(LogLevel::Error, &format!("Could not find pid {pid} from ZwAllocateVirtualMemory signal from {:?}.", syscall_origin));
            return;
        };
        
        // todo determine different rwx permissions in the future once implemented.
        process.add_ghost_hunt_timer(syscall_origin, EventTypeWeighted::VirtualAllocEx);

    }
}

impl ProcessImpl for Process {
    /// Updates the risk score for a given process. The input score argument may be positive or negative
    /// within the bounds of the type; this will alter the score accordingly
    fn update_process_risk_score(&mut self, score: EventTypeWeighted) {

        if self.risk_score.checked_add_signed(score as i16).is_none() {
            // If we overflowed the unsigned int / went below zero, just assign a score of 0
            // todo this could possibly be abused by an adversary brute forcing a 0 score?
            self.risk_score = 0;
        }
    }
    
    /// Start a ghost hunt timer for a given API you are monitoring for Ghost Hunting.
    /// 
    /// This function does not deal with additional ghost hunting parameters, environment logic etc, this function deals
    /// solely with the handling of a ghost hunt timer.
    /// 
    /// In the event an API timer is added, and one exists from the opposite source, then it will be removed as per my 
    /// ghost hunting technique - this means there was a successful match and no apparent syscall evasion took place.
    fn add_ghost_hunt_timer(&mut self, notification_origin: ApiOrigin, event_type: EventTypeWeighted) {

        // Get information on what API's are able to cancel out the ghost timers.
        let cancellable_by = EventTypeWeighted::cancellable_by(&event_type);

        // If the timers are empty; then its the first in so we can add it to the list straight up.
        // Else, we will look for a match on the type.
        if self.ghost_hunting_timers.is_empty() {
            let timer = {
                let mut t = GhostHuntingTimers {
                    timer: SystemTime::now(),
                    event_type: event_type.clone(),
                    origin: notification_origin.clone(),
                    cancellable_by,
                };
    
                // remove the current notification from the cancellable by (prevent dangling timers)
                if remove_cancellable_by_match(&mut t, &notification_origin).is_none() {
                    let logger = Log::new();
                    logger.panic(&format!("Could not find {:?} in timer. This should never happen.", notification_origin));
                }
    
                t
            };
            self.ghost_hunting_timers.push(timer);
        } else {
            let mut index: usize = 0;
            for timer in &mut self.ghost_hunting_timers {
                // Pf the API Origin that this fn relates to is found in the list of cancellable APIs then cancel them out.
                // Part of the core Ghost Hunting logic
                // if all the cancellation signals received, remove the timer.
                if remove_cancellable_by_match(timer, &notification_origin).is_some() {
                    if timer.cancellable_by.is_empty() {
                        self.ghost_hunting_timers.remove(index);
                    }
                    return
                };

                index += 1;
            }

            // we did not match, so add the element 
            let timer = {
                let mut t = GhostHuntingTimers {
                    timer: SystemTime::now(),
                    event_type: event_type.clone(),
                    origin: notification_origin.clone(),
                    cancellable_by,
                };
    
                // remove the current notification from the cancellable by (prevent dangling timers)
                if remove_cancellable_by_match(&mut t, &notification_origin).is_none() {
                    let logger = Log::new();
                    logger.panic(&format!("Could not find {:?} in timer. This should never happen.", notification_origin));
                }
    
                t
            };
            self.ghost_hunting_timers.push(timer);
        }
    }
}

/// Remove an API from a given Ghost Hunting timer.
/// 
/// This function will modify the timer to remove a cancellable API origin from the Vec.
/// 
/// # Returns
/// - Some: If this function found a cancelable origin type, it will return Some
/// - None: If the cancellable type was not found, it will return none.
fn remove_cancellable_by_match(timer: &mut GhostHuntingTimers, api_origin: &ApiOrigin) -> Option<()> {
    if let Some(index) = timer.cancellable_by.iter().position(|x| *x == *api_origin) {         
        timer.cancellable_by.remove(index);
        return Some(());
    }

    None
}

/// Enumerate all processes and add them to the active process monitoring hashmap.
pub async fn snapshot_all_processes() -> ProcessMonitor {

    let logger = Log::new();
    let mut all_processes = ProcessMonitor::new();
    let mut processes_cache: Vec<ProcessStarted> = vec![];

    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0)} {
        Ok(s) => {
            if s.is_invalid() {
                logger.panic(&format!("Unable to create snapshot of all processes. GLE: {}", unsafe { GetLastError().0 }));
            } else {
                s
            }
        },
        Err(_) => {
            // not really bothered about the error at this stage
            logger.panic(&format!("Unable to create snapshot of all processes. GLE: {}", unsafe { GetLastError().0 }));
        },
    };

    let mut process_entry = PROCESSENTRY32::default();
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot,&mut process_entry)}.is_ok() {
        loop {
            // 
            // Get the process name; helpful mostly for debug messages
            //
            let current_process_name_ptr = process_entry.szExeFile.as_ptr() as *const _;
            let current_process_name = match unsafe { CStr::from_ptr(current_process_name_ptr) }.to_str() {
                Ok(process) => process.to_string(),
                Err(e) => {
                    logger.log(LogLevel::Error, &format!("Error converting process name. {e}"));
                    if !unsafe { Process32Next(snapshot, &mut process_entry) }.is_ok() {
                        break;
                    }
                    continue;
                }
            };

            //
            // Get the full image of the process
            //
            let res = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, process_entry.th32ProcessID)};
            let h_process = match res {
                Ok(h) => h,
                Err(e) => {
                    logger.log(LogLevel::NearFatal, 
                        &format!("Failed to get a handle to process: {}. Error: {e}", current_process_name)
                    );
                    if !unsafe { Process32Next(snapshot, &mut process_entry) }.is_ok() {
                        break;
                    }
                    continue;
                },
            };

            let mut out_str: Vec<u8> = vec![0; MAX_PATH as _];
            let mut len = out_str.len() as u32;

            let res = unsafe {
                QueryFullProcessImageNameA(
                    h_process, 
                    PROCESS_NAME_FORMAT::default(), 
                    PSTR::from_raw(out_str.as_mut_ptr()),
                    &mut len,
                )
            };
            if res.is_err() {
                logger.log(LogLevel::NearFatal, 
                    &format!("Failed to query full image name for process: {}. Error: {}", current_process_name, unsafe {GetLastError().0})
                );
                if !unsafe { Process32Next(snapshot, &mut process_entry) }.is_ok() {
                    break;
                }
                continue;
            }

            let full_img_path = unsafe {CStr::from_ptr(out_str.as_ptr() as *const _)}.to_string_lossy().into_owned();

            let process = ProcessStarted {
                image_name: full_img_path.clone(),
                command_line: "".to_string(),
                parent_pid: process_entry.th32ParentProcessID as u64,
                pid: process_entry.th32ProcessID as u64,
            };

            processes_cache.push(process);

            // continue enumerating
            if !unsafe { Process32Next(snapshot, &mut process_entry) }.is_ok() {
                break;
            }
        }
    }

    unsafe { let _ = CloseHandle(snapshot); };

    // Now the HANDLE is closed we are able to call the async function insert on all_processes. 
    // We could not do this before closing the handle as teh HANDLE (aka *mut c_void) is not Send
    for process in processes_cache {
        if let Err(e) = all_processes.onboard_new_process(&process).await {
            match e {
                super::process_monitor::ProcessErrors::DuplicatePid => {
                    logger.log(LogLevel::Error, &format!("Duplicate PID found in process hashmap, did not insert. Pid in question: {}", process_entry.th32ProcessID));
                },
                _ => {
                    logger.log(LogLevel::Error, "An unknown error occurred whilst trying to insert into process hashmap.");
                }
            }
        };
    }

    all_processes
}


/// Inject the EDR's DLL into a given process by PID. This should be done for processes running on start, and for 
/// processes which are newly created.
fn inject_edr_dll(pid: u64) -> Result<(), ProcessErrors> {
    // Open the process
    let h_process = unsafe { OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid as u32) };
    let h_process = match h_process {
        Ok(h) => h,
        Err(_) => return Err(ProcessErrors::FailedToOpenProcess),
    };

    // Get a handle to Kernel32.dll
    let h_kernel32 = unsafe { GetModuleHandleA(s!("Kernel32.dll")) };
    let h_kernel32 = match h_kernel32 {
        Ok(h) => h,
        Err(_) => return Err(ProcessErrors::BadHandle),
    };

    // Get a function pointer to LoadLibraryA from Kernel32.dll
    let load_library_fn_address = unsafe { GetProcAddress(h_kernel32, s!("LoadLibraryA")) };
    let load_library_fn_address = match load_library_fn_address {
        None => return Err(ProcessErrors::BadFnAddress),
        Some(address) => address as *const (),
    };

    // Allocate memory for the path to the DLL
    // todo needs moving to an admin location
    let username = get_logged_in_username().unwrap();
    let base_path = format!("C:\\Users\\{username}\\AppData\\Roaming\\");
    let dll_path = format!("{}{}\0", base_path, SANCTUM_DLL_RELATIVE_PATH);
    let path_len = dll_path.len();

    let remote_buffer_base_address = unsafe {
        VirtualAllocEx(h_process,
                        None,
                        path_len,
                        MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE,
    ) };

    if remote_buffer_base_address.is_null() {
        return Err(ProcessErrors::BaseAddressNull);
    }

    // Write to the buffer
    let mut bytes_written: usize = 0;
    let buff_result = unsafe {
        WriteProcessMemory(
            h_process, 
            remote_buffer_base_address, 
            dll_path.as_ptr() as *const  _,
            path_len, 
            Some(&mut bytes_written as *mut usize
        ))
    };

    if buff_result.is_err() {
        return Err(ProcessErrors::FailedToWriteMemory);
    }

    // correctly cast the address of LoadLibraryA
    let load_library_fn_address: Option<unsafe extern "system" fn(*mut c_void) -> u32> = Some(
        unsafe { std::mem::transmute(load_library_fn_address) }
    );

    // Create thread in process
    let mut thread: u32 = 0;
    let h_thread = unsafe { CreateRemoteThread(
        h_process,
        None, // default security descriptor
        0, // default stack size
        load_library_fn_address,
        Some(remote_buffer_base_address),
        0,
        Some(&mut thread as *mut u32),
    )};

    if h_thread.is_err() {
        return Err(ProcessErrors::FailedToCreateRemoteThread);
    }

    Ok(())
}