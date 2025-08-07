use serde::{Deserialize, Serialize};

/// Bitfields which act as a mask to determine which event types (kernel, syscall hook, etw etc)
/// are required to fully cancel out the ghost hunt timers.
///
/// This is because not all events are capturable in the kernel without tampering with patch guard etc, so there are some events
/// only able to be caught by ETW and the syscall hook.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum SyscallEventSource {
    EventSourceKernel = 0x1,
    EventSourceSyscallHook = 0x2,
}

/// A wrapper for IPC messages sent by the injected DLL in all processes. This allows the same IPC interface to
/// be used across any number of IPC senders, so long as the enum has a discriminant for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DLLMessage {
    SyscallWrapper(Syscall),
    NtdllOverwrite,
}

/****************************** SYSCALLS *******************************/

/// Information relating to a syscall event which happened on the device. This struct holds:
///
/// - `data`: This field is generic over T which must implement the `HasPid` trait. This field contains the metadata associated
/// with the syscall.
/// - `source`: Where the system event was captured, e.g. a hooked syscall, ETW, or the driver.
/// - `evasion_weight`: The weight associated with the event if EDR evasion is detected.
/// - todo: `event_weight` for general weighting if this occurs, same as the normal weight i guess?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Syscall {
    pub nt_function: NtFunction,
    pub pid: u64,
    pub source: SyscallEventSource,
    pub evasion_weight: i16,
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NtFunction {
    NtOpenProcess(Option<NtOpenProcessData>),
    NtWriteVirtualMemory(Option<NtWriteVirtualMemoryData>),
    NtAllocateVirtualMemory(Option<NtAllocateVirtualMemory>),
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtOpenProcessData {
    pub target_pid: u32,
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtWriteVirtualMemoryData {
    pub target_pid: u32,
    pub base_address: usize,
    pub buf_len: usize,
}


unsafe impl Send for Syscall {}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtAllocateVirtualMemory {
    pub dest_pid: u32,
    pub base_address: usize,
    pub sz: usize,
    pub alloc_type: u32,
    pub protect_flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtOpenProcess {
    pub target_pid: u32,
    pub acces_mask: u32,
}