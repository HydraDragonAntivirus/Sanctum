use alloc::{format, string::{String, ToString}, vec::Vec};
use shared_no_std::constants::SanctumVersion;
use wdk::println;
use wdk_sys::{ntddk::RtlUnicodeStringToAnsiString, FALSE, STATUS_SUCCESS, STRING, UNICODE_STRING};

/// A custom error enum for the Sanctum driver
pub enum DriverError {
    NullPtr,
    LengthTooLarge,
    Unknown(String)
}

pub trait ToUnicodeString {
    fn to_unicode_string(&self) -> Option<UNICODE_STRING>;
}

impl ToUnicodeString for Vec<u16> {
    fn to_unicode_string(&self) -> Option<UNICODE_STRING> {
        create_unicode_string(self)
    }
}

impl ToUnicodeString for &str {
    fn to_unicode_string(&self) -> Option<UNICODE_STRING> {
        let v = self.to_u16_vec();
        create_unicode_string(&v)
    }
}

/// Creates a Windows API compatible unicode string from a u16 slice.
///
///
/// <h1>Returns</h1>
/// Returns an option UNICODE_STRING, if the len of the input string is 0 then
/// the function will return None.
pub fn create_unicode_string(s: &Vec<u16>) -> Option<UNICODE_STRING> {
    //
    // Check the length of the input string is greater than 0, if it isn't,
    // we will return none
    //
    let len = if s.len() > 0 {
        s.len()
    } else {
        return None;
    };

    //
    // Windows docs specifies for UNICODE_STRING:
    //
    // param 1 - length, Specifies the length, in bytes, of the string pointed to by the Buffer member,
    // not including the terminating NULL character, if any.
    //
    // param 2 - max len, Specifies the total size, in bytes, of memory allocated for Buffer. Up to
    // MaximumLength bytes may be written into the buffer without trampling memory.
    //
    // param 3 - buffer, Pointer to a wide-character string
    //
    // Therefore, we will do the below check to remove the null terminator from the len

    let len_checked = if len > 0 && s[len - 1] == 0 {
        len - 1
    } else {
        len
    };

    Some(UNICODE_STRING {
        Length: (len_checked * 2) as u16,
        MaximumLength: (len * 2) as u16,
        Buffer: s.as_ptr() as *mut u16,
    })
}


pub trait ToU16Vec {
    fn to_u16_vec(&self) -> Vec<u16>;
}

impl ToU16Vec for &str {
    fn to_u16_vec(&self) -> Vec<u16> {
        // reserve space for null terminator
        let mut buf = Vec::with_capacity(self.len() + 1);

        // iterate over each char and push the UTF-16 to the buf
        for c in self.chars() {
            let mut c_buf = [0; 2];
            let encoded = c.encode_utf16(&mut c_buf);
            buf.extend_from_slice(encoded);
        }

        buf.push(0); // add null terminator
        buf
    }
}


/// Checks the compatibility of the driver and client versions based on major.minor.patch fields.
/// 
/// # Returns
/// 
/// True if compatible, false otherwise.
pub fn check_driver_version(client_version: &SanctumVersion) -> bool {

    // only compatible with versions less than 1
    if client_version.major >= 1 {
        return false;
    }

    true
}

/// Converts a UNICODE_STRING into a valid String (lossy) that can be printed
pub fn unicode_to_string(input: *const UNICODE_STRING) -> Result<String, DriverError> {
    
    const MAX_LEN: u16 = 256;
    
    if input.is_null() {
        println!("[sanctum] [-] Error converting unicode string to string, null pointer.");
        return Err(DriverError::NullPtr);
    }

    // if we aren't dereferencing a null pointer checked above, then check the length of the input string isn't greater
    // than our buffer max length we are going to write to
    unsafe {
        if (*input).Length >= MAX_LEN {
            println!("[sanctum] [-] Len of input UNICODE_STRING {} is greater than MAX_LEN {}.", (*input).Length, MAX_LEN);
            return Err(DriverError::LengthTooLarge);
        }
    }

    // todo can probably do straight from UNICODE_STRING no need to convert
    let mut buf: [i8; MAX_LEN as usize] = [0; MAX_LEN as usize]; 
    let mut s: STRING = STRING {
        Length: 0,
        MaximumLength: MAX_LEN, // give it the max len of a u16
        Buffer: &mut buf as *mut i8,
    };

    //
    // Convert the unicode string to an ANSI string, then we will construct a normal String from raw parts - this may be extra conversion than 
    // converting the unicode string from raw parts without the above step. Doing so was resulting in bsod, trying to diagnose.
    // todo
    //
    let res = unsafe {
        RtlUnicodeStringToAnsiString(&mut s, input, FALSE as u8)
    };

    if res != STATUS_SUCCESS {
        return Err(DriverError::Unknown(format!("Error converting UNICODE_STRING to ANSI String. Code: {res}")));
    }

    let s = unsafe {
        let slice = core::slice::from_raw_parts(s.Buffer as *const u8, s.Length as usize);
        String::from_utf8_lossy(slice).to_string()
    };

    Ok(s)
}