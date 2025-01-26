use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

/// The Process is a structural representation of an individual process thats
/// running on the host machine, and keeping track of risk scores, and activity conducted
/// by processes. 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub pid: u64,
    pub process_image: String,
    pub commandline_args: String,
    pub risk_score: u16,
    pub allow_listed: bool, // whether the application is allowed to exist without monitoring
    pub sanctum_protected_process: bool, // scc (sanctum protected process) defines processes which require additional protections from access / abuse, such as lsass.exe.
    /// Creates a time window in which a process handle must match from a hooked syscall with
    /// the kernel receiving the notification. Failure to match this may be an indicator of hooked syscall evasion.
    pub ghost_hunting_timers: Vec<GhostHuntingTimers>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostHuntingTimers {
    pub pid: u32,
    pub timer: SystemTime,
    pub syscall_type: SyscallType,
    pub origin: ApiOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Syscall {
    OpenProcess(OpenProcessData),
    VirtualAllocEx(VirtualAllocExData)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenProcessData {
    pub pid: u32,
    pub target_pid: u32,
}


/// Data relating to arguments / local environment information when the hooked syscall ZwAllocateVirtualMemorry
/// is called by a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualAllocExData {
    /// The base address is the base of the remote process which is stored as a usize but is actually a hex
    /// address and will need converting if using as an address.
    pub base_address: usize,
    /// THe size of the allocated memory
    pub region_size: usize,
    /// A bitmask containing flags that specify the type of allocation to be performed. 
    pub allocation_type: u32,
    /// A bitmask containing page protection flags that specify the protection desired for the committed 
    /// region of pages.
    pub protect: u32,
    /// The pid in which the allocation is taking place in
    pub remote_pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum SyscallType {
    OpenProcess = 20,
    VirtualAllocExRWX = 50,
    CreateRemoteThread = 60,
}

/// Defines whether a syscall type API was caught in the kernel or in a syscall hook
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApiOrigin {
    Kernel,
    SyscallHook,
}