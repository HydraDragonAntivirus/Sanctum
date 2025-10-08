use core::{arch::asm, ffi::c_void, iter::once, ptr::null_mut, sync::atomic::Ordering};

use alloc::vec::Vec;
use wdk::{nt_success, println};
use wdk_sys::{
    HANDLE, MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, PVOID, UNICODE_STRING,
    ntddk::{
        PsGetCurrentProcessId, RtlCopyMemoryNonTemporal, RtlInitUnicodeString,
        ZwAllocateVirtualMemory,
    },
};

use crate::{
    core::process_monitor::{MONITORED_FN_PTRS, SensitiveAPI},
    ffi::ZwProtectVirtualMemory,
    utils::get_process_name,
};

// todo this needs to work for all users -> maybe its a System32 job
const SANCTUM_HOOK_DLL_PATH: &str = r"\??\C:\Users\flux\AppData\Roaming\Sanctum\sanctum.dll";

/// Injects the sanctum DLL which hooks NTDLL into the current process (must be called from an image load callback).
///
/// Methodology graciously provided by https://github.com/eversinc33, including the bootstrapping shellcode and using
/// LdrLoadDll to make this work, I was having trouble with some instability and he donated his methodology :) thank you!
pub fn inject_dll() {
    let pid = unsafe { PsGetCurrentProcessId() } as u32;
    let img_name = get_process_name();

    println!("[sanctum] [i] Injecting into process {img_name}, pid: {pid}",);

    let dll_path_to_inject = generate_unicode_path_for_dll();

    //
    // Shellcode to load a DLL into a process via LdrLoadDll
    //
    let shellcode: [u8; 47] = [
        0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
        0x48, 0x31, 0xD2, // xor rdx, rdx
        0x48, 0x31, 0xC9, // xor rcx, rcx
        0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov r8, [remoteUnicodeString]
        0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, // mov r9, [handleOut]
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, [LdrLoadDll]
        0xFF, 0xD0, // call rax
        0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
        0xC3, // ret
    ];

    println!("Shellcode addr: {:p}", &shellcode);

    //
    // Allocate memory for the DLL name and the unicode_string struct
    //
    let dll_name_len: usize = dll_path_to_inject.Length as usize + size_of::<u16>(); // include space for null terminator
    let mut shellcode_size = shellcode.len() as u64;
    let mut total_size: u64 =
        shellcode_size + size_of::<UNICODE_STRING>() as u64 + size_of::<*const c_void>() as u64;
    let mut remote_shellcode_memory = null_mut();
    let mut remote_memory = null_mut();

    let cur_proc_handle: HANDLE = (-1isize) as HANDLE;

    let status = unsafe {
        ZwAllocateVirtualMemory(
            cur_proc_handle,
            &mut remote_shellcode_memory,
            0,
            &mut shellcode_size,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if !nt_success(status) {
        println!(
            "[sanctum] [-] DLL injection failed on ZwAllocateVirtualMemory with status: {status:#X}"
        );
        return;
    }

    let status = unsafe {
        ZwAllocateVirtualMemory(
            cur_proc_handle,
            &mut remote_memory,
            0,
            &mut total_size,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if !nt_success(status) {
        println!(
            "[sanctum] [-] DLL injection failed on ZwAllocateVirtualMemory 2 with status: {status:#X}"
        );
        return;
    }

    //
    // Structure of memory:
    //
    // 1 - Shellcode R(W)X
    //
    // 2 - UNICODE_STRING RW
    //   - OUT HANDLE
    //   - Dll Name
    //

    let remote_unicode_string = remote_memory;
    let remote_handle_out = (remote_memory as usize + size_of::<UNICODE_STRING>()) as *mut c_void;
    let remote_dll_name = (remote_memory as usize
        + size_of::<UNICODE_STRING>()
        + size_of::<*mut c_void>()) as *mut c_void;

    let ldr_ld_dll_addr = {
        let p_mon_apis = MONITORED_FN_PTRS.load(Ordering::SeqCst);
        let mut addr: usize = 0;

        if !p_mon_apis.is_null() {
            let mon = unsafe { &*p_mon_apis };

            for api in &mon.inner {
                if api.1.1 == SensitiveAPI::LdrLoadDll {
                    addr = *api.0;
                    break;
                }
            }
        }

        addr
    };

    if ldr_ld_dll_addr == 0 {
        println!("[sanctum] [-] Failed to get address of LdrLoadDll whilst trying DLL injection.");
        return;
    }

    //
    // Memory patching
    //

    unsafe {
        //
        // Write to the shellcode block with the newly allocated addresses and addr of LdrLoadDll
        //

        // todo we are just writing zeros.. except for the last call which does copy the address..
        // maybe cos its ldr_ld_dll_addr as *const usize as *const c_void -> as a usize first?
        let dst = (shellcode.as_ptr() as usize + 12) as *mut c_void;
        let src = remote_unicode_string as *const *const c_void as *const c_void;
        println!(
            "Writing 1, {dst:p}, src: {src:p}, len: {}.",
            size_of::<PVOID>() as u64
        );
        RtlCopyMemoryNonTemporal(dst, src, size_of::<PVOID>() as u64);

        let dst = (shellcode.as_ptr() as usize + 22) as *mut c_void;
        println!("Writing 2, {dst:p}, src: {remote_handle_out:p}.");
        RtlCopyMemoryNonTemporal(dst, remote_handle_out, size_of::<PVOID>() as u64);

        let dst = (shellcode.as_ptr() as usize + 32) as *mut c_void;
        println!(
            "Writing 3, {dst:p}, src: {:p}.",
            ldr_ld_dll_addr as *const usize as *const c_void
        );
        RtlCopyMemoryNonTemporal(
            dst,
            &ldr_ld_dll_addr as *const usize as *const c_void,
            size_of::<usize>() as u64,
        );

        println!("Done 3");

        asm!("int3");

        // Patch in the shellcode to the remote region in the target process
        RtlCopyMemoryNonTemporal(
            remote_shellcode_memory,
            shellcode.as_ptr() as *const _,
            shellcode_size,
        );

        // Write the DLL name
        RtlCopyMemoryNonTemporal(
            remote_dll_name,
            dll_path_to_inject.Buffer as *const _,
            dll_name_len as u64,
        );

        let mut remote_unicode = UNICODE_STRING::default();
        remote_unicode.Length = dll_path_to_inject.Length;
        remote_unicode.MaximumLength = dll_path_to_inject.MaximumLength;
        remote_unicode.Buffer = remote_dll_name as *mut u16;

        RtlCopyMemoryNonTemporal(
            remote_unicode_string,
            &remote_unicode as *const UNICODE_STRING as *const c_void,
            size_of::<UNICODE_STRING>() as u64,
        );

        //
        // Make shellcode executable
        //
        let mut op = 0;
        let status = ZwProtectVirtualMemory(
            cur_proc_handle,
            &mut remote_shellcode_memory,
            &mut shellcode_size,
            PAGE_EXECUTE_READ,
            &mut op,
        );

        if !nt_success(status) {
            println!(
                "[sanctum] [-] Failed to mark shellcode memory as executable. Status: {status:#X}"
            );
            // todo free memory
        }

        println!(
            "[sanctum] [+] All allocations succeeded. Shellcode at: {:p}",
            remote_shellcode_memory
        );
    }
}

fn generate_unicode_path_for_dll() -> UNICODE_STRING {
    let path: Vec<u16> = SANCTUM_HOOK_DLL_PATH
        .encode_utf16()
        .chain(once(0))
        .collect();

    let mut us = UNICODE_STRING::default();

    unsafe { RtlInitUnicodeString(&mut us, path.as_ptr()) };

    us
}
