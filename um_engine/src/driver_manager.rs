use core::str;
use std::{ffi::c_void, ptr::null_mut};

use shared::{constants::{DEVICE_NAME_PATH, SVC_NAME, SYMBOLIC_NAME_PATH, SYS_INSTALL_RELATIVE_LOC}, ioctl::SANC_IOCTL_PING};
use windows::{
    core::{Error, PCWSTR}, 
    Win32::{
        Foundation::{CloseHandle, GetLastError, ERROR_DUPLICATE_SERVICE_NAME, ERROR_SERVICE_EXISTS, GENERIC_READ, GENERIC_WRITE, HANDLE, UNICODE_STRING}, Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING}, System::{Services::{CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, StartServiceW, SC_HANDLE, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER, SERVICE_STATUS}, IO::DeviceIoControl}
}};

use crate::{driver_manager, strings::{ToUnicodeString, ToWindowsUnicodeString}};


/// The SanctumDriverManager holds key information to be shared between
/// modules which relates to uniquely identifiable attributes such as its name 
/// and other critical settings.
pub struct SanctumDriverManager<'a> {
    pub device_name_path: UNICODE_STRING,
    pub symbolic_link: UNICODE_STRING,
    svc_path: &'a str,
    svc_name: &'a str,
    pub handle_via_path: DriverHandleRaii,
}

impl<'a> SanctumDriverManager<'a> {
    /// Generate a new instance of the driver manager, which initialises the device name path and symbolic link path
    pub fn new() -> SanctumDriverManager<'a> {

        // 
        // Generate the UNICODE_STRING values for the device and symbolic name
        //
        let device_name_path = DEVICE_NAME_PATH.to_u16_vec().to_windows_unicode_string().unwrap();
        let symbolic_link = SYMBOLIC_NAME_PATH.to_u16_vec().to_windows_unicode_string().unwrap();
        
        // BUG path needs to be absolute, this should fix the issue where it is not being 
        // installed & ran correctly
        let install_path = SYS_INSTALL_RELATIVE_LOC;
        
        let svc_name = SVC_NAME;

        let mut instance = SanctumDriverManager {
            device_name_path,
            symbolic_link,
            svc_path: install_path,
            svc_name,
            handle_via_path: DriverHandleRaii::default(), // set to None
        };

        // attempt to initialise a handle to the driver, this may silently fail - and will do so in the case
        // where the driver is not yet installed (or has been uninstalled)
        instance.init_handle_via_registry();

        instance
    }
    

    /// Command for the driver manager to install the driver on the target device.
    /// 
    /// # Panics
    /// 
    /// This function will panic if it was unable to open the service manager or install the driver
    /// in most cases. ERROR_SERVICE_EXISTS, ERROR_DUPLICATE_SERVICE_NAME will not panic.
    pub fn install_driver(&mut self) {
        
        // 
        // Create a new ScDbMgr to hold the handle of the result of the OpenSCManagerW call.
        //
        let mut sc_mgr = ServiceInterface::new();
        sc_mgr.open_service_manager_w(SC_MANAGER_ALL_ACCESS);
        let svc_name = PCWSTR::from_raw(self.svc_name.to_u16_vec().as_ptr());
        let svc_path = PCWSTR::from_raw(self.svc_path.to_u16_vec().as_ptr());

        //
        // Install the driver on the device
        // 
        let handle = unsafe {
            match CreateServiceW(
                sc_mgr.sc_db_handle.unwrap(), 
                svc_name,  // service name
                svc_name,  // display name
                SERVICE_ALL_ACCESS, 
                SERVICE_KERNEL_DRIVER, 
                SERVICE_DEMAND_START, 
                SERVICE_ERROR_NORMAL, 
                svc_path,
                None, 
                None, 
                None, 
                None, 
                None,
            ) {
                Ok(h) => {
                    if h.is_invalid() {
                        panic!("[-] Handle returned is invalid when attempting to install the service. Last error: {:?}", GetLastError());
                    }

                    h
                },
                Err(e) => {
                    let le = GetLastError();

                    match le {
                        ERROR_DUPLICATE_SERVICE_NAME => {
                            eprintln!("[-] Unable to create service, duplicate service name found.");
                            return;
                        },
                        ERROR_SERVICE_EXISTS => {
                            eprintln!("[-] Unable to create service, service already exists.");
                            return;
                        }
                        _ => {
                            // anything else
                            panic!("[-] Unable to create service. Error: {e}");
                        }
                    } // close match last err

                },
            } // close match handle result
        };

        println!("[+] Driver successfully installed.");

        //
        // At this point, we should have the handle, and we can close it.
        //

        if !handle.is_invalid() {
            if let Err(e) = unsafe { CloseServiceHandle(handle) } {
                eprintln!("[-] Unable to close handle after installing service. Error: {e}");
            }
        }
    }


    /// Start the driver.
    /// 
    /// # Panics
    /// 
    /// Function will panic if it cannot open a handle to the SC Manager
    pub fn start_driver(&mut self) {
        // 
        // Create a new ScDbMgr to hold the handle of the result of the OpenSCManagerW call.
        //
        let mut sc_mgr = ServiceInterface::new();
        sc_mgr.open_service_manager_w(SC_MANAGER_ALL_ACCESS);

        // get a handle to sanctum service
        if let Err(e) = sc_mgr.get_handle_to_sanctum_svc(self) {
            eprintln!("[-] Failed to get handle to the Sanctum service when attempting to start it. {e}");
            return;
        }

        unsafe {
            if let Err(e) = StartServiceW(
                sc_mgr.sanctum_handle.unwrap(), 
                None,
            ){
                eprintln!("[-] Failed to start service. {e}. Handle: {:?}.", sc_mgr.sc_db_handle.unwrap());
                return;
            };
        };

        // try to get a handle now the driver has started
        self.init_handle_via_registry();

        println!("[+] Driver started successfully.");
    }


    /// Stop the driver
    /// 
    /// # Panics
    /// 
    /// Function will panic if it cannot open a handle to the SC Manager
    pub fn stop_driver(&mut self) {
        let mut sc_mgr = ServiceInterface::new();
        sc_mgr.open_service_manager_w(SC_MANAGER_ALL_ACCESS);

        // get a handle to sanctum service
        if let Err(e) = sc_mgr.get_handle_to_sanctum_svc(self) {
            eprintln!("[-] Failed to get handle to the Sanctum service when attempting to start it. {e}");
            return;
        }

        let mut service_status = SERVICE_STATUS::default();

        if let Err(e) = unsafe {
            ControlService(
                sc_mgr.sanctum_handle.unwrap(), 
                SERVICE_CONTROL_STOP, 
                &mut service_status,
            )
        } {
            // if was error
            eprintln!("[-] Failed to stop the service, {e}. Handle: {:?}", sc_mgr.sc_db_handle.unwrap());
        }

        // delete our local reference to the driver handle
        self.handle_via_path = DriverHandleRaii::default(); // drop will be invoked closing the handle

        println!("[+] Driver stopped successfully.");

    }


    /// Uninstall the driver.
    ///
    /// # Panics
    /// 
    /// Function will panic if it cannot open a handle to the SC Manager
    pub fn uninstall_driver(&self) {
        let mut sc_mgr = ServiceInterface::new();
        sc_mgr.open_service_manager_w(SC_MANAGER_ALL_ACCESS);

        // get a handle to sanctum service
        if let Err(e) = sc_mgr.get_handle_to_sanctum_svc(self) {
            eprintln!("[-] Failed to get handle to the Sanctum service when attempting to start it. {e}");
            return;
        }

        if let Err(e) = unsafe { DeleteService(sc_mgr.sanctum_handle.unwrap())} {
            eprintln!("[-] Failed to uninstall the driver: {e}. Handle: {:?}", sc_mgr.sc_db_handle.unwrap());
        }

        println!("[+] Driver uninstalled successfully.");
    }


    /// Gets a handle to the driver via its registry path using CreateFile to obtain the handle. This function
    /// may silently fail if the driver is not installed, or there is some other error.
    /// 
    /// If unsuccessful, the handle field will be None; otherwise it will be Some(handle). The handle is managed
    /// by Rust's RAII Drop trait so no requirement to manually close the handle.
    /// 
    /// todo better error handling for this fn.
    pub fn init_handle_via_registry(&mut self) {

        println!("[i] Driver name path buffer: {:?}", self.device_name_path.Buffer);

        let handle  = unsafe {
            CreateFileW(
                self.device_name_path.Buffer,
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };

        match handle {
            Ok(h) => self.handle_via_path.handle = Some(h),
            Err(e) => {
                eprintln!("[-] Unable to get handle to driver via its registry path, error: {e}");
            },
        }
    }



    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /////////////////////////////////////////////////// IOCTLS ////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    // All IOCTL functions should start with ioctl_

    /// Ping the driver from usermode
    pub fn ioctl_ping_driver(&self) {
        //
        // Check the handle to the driver is valid, if not, attempt to initialise it.
        //

        // todo improve how the error handling happens..
        if self.handle_via_path.handle.is_none() {
            eprintln!("[-] Handle to the driver is not initialised; please ensure you have started / installed the service. Unable to pass IOCTL.");
            return;
        }
    
        //
        // If we have a handle
        //

        let message = "Hello world";
        const RESP_SIZE: u32 = 256;
        let response: [u8; RESP_SIZE as usize] = [0; RESP_SIZE as usize]; // gets mutated in unsafe block
        let mut bytes_returned: u32 = 0; 

        // attempt the call
        let result = unsafe {
            DeviceIoControl(
                self.handle_via_path.handle.unwrap(), 
                SANC_IOCTL_PING, 
                Some(message.as_ptr() as *const c_void), 
                message.len() as u32, 
                Some(response.as_ptr() as *mut c_void),
                RESP_SIZE, 
                Some(&mut bytes_returned), 
                None)
        };

        if let Err(e) = result {
            eprintln!("Error from attempting IOCTL call. {e}");
            // no cleanup required, no additional handles or heap objects
            return;
        }

        // parse out the result
        if let Ok(response) = str::from_utf8(&response[..bytes_returned as usize]) {
            println!("[+] Bytes returned: {bytes_returned} response: {:#?}", response);
        } else {
            println!("[-] Error parsing response as UTF-8");
        }
    }
}


pub struct DriverHandleRaii {
    pub handle: Option<HANDLE>,
}

impl Default for DriverHandleRaii {
    fn default() -> Self {
        Self { handle: None }
    }
}

impl Drop for DriverHandleRaii {
    fn drop(&mut self) {
        if self.handle.is_some() && !self.handle.unwrap().is_invalid() {
            println!("[i] Dropping driver handle.");
            let _ = unsafe { CloseHandle(self.handle.unwrap()) };
            self.handle = None;
        }
    }
}


/// A custom struct to hold a SC_HANDLE. This struct implements the drop trait so that
/// when it goes out of scope, it will clean up its handle so you do not need to remember 
/// to call CloseServiceHandle.
struct ServiceInterface { 
    sc_db_handle: Option<SC_HANDLE>,
    sanctum_handle: Option<SC_HANDLE>,
}

impl ServiceInterface {
    /// Open a handle to the SC Manager, storing the resulting handle in the instance.
    /// 
    /// # Panics
    /// 
    /// If the call to OpenServiceManagerW fails, this will panic.
    fn open_service_manager_w(
        &mut self,
        dw_desired_access: u32,
    ) {
        self.sc_db_handle = unsafe {
            match OpenSCManagerW(
               None, 
               None, 
               dw_desired_access,
           ) {
               Ok(h) => Some(h),
               Err(e) => panic!("[-] Unable to open service manager handle, {e}."),
           }
       }
    }


    /// Attempt to obtain a handle to the Sanctum service. If this is successful the function returns
    /// a Result<()>, and the field sanctum_handle is given the value of the handle.
    /// 
    /// The handle will automatically be closed when it goes out of scope as it is implemented in the 
    /// drop trait.
    fn get_handle_to_sanctum_svc(&mut self, driver_manager: &SanctumDriverManager) -> Result<(), Error> {
        
        println!("[i] Service name: {}", driver_manager.svc_name);

        let svc_name: PCWSTR = PCWSTR::from_raw(driver_manager.svc_name.to_u16_vec().as_ptr());

        println!("[i] As ptr: {:?}", svc_name);

        let driver_handle = unsafe { OpenServiceW(
            self.sc_db_handle.unwrap(), 
            svc_name, 
            SERVICE_ALL_ACCESS) 
        }?;

        self.sanctum_handle = Some(driver_handle);

        // we return nothing, as the field sanctum_handle is set on success
        Ok(())
       }


    /// Instantiates the ServiceInterface with a null handle.
    fn new() -> ServiceInterface {
        ServiceInterface { 
            sc_db_handle: None,
            sanctum_handle: None,
        }
    }
}

impl Drop for ServiceInterface {
    /// Automatically close the service handle if it is valid
    fn drop(&mut self) {
        //
        // Close the handle for the SC DB
        //
        if self.sc_db_handle.is_none() {
            return;
        }

        if self.sc_db_handle.unwrap().0 != null_mut() {
            if let Err(e) = unsafe { CloseServiceHandle(self.sc_db_handle.unwrap()) } {
                eprintln!("[-] Unable to close handle after installing service. Error: {e}");
            }
            self.sc_db_handle = None;
        } else {
            eprintln!("[-] Unable to close handle, handle was null!");
        }


        //
        // Close the handle to the sanctum driver
        //
        if self.sanctum_handle.is_none() {
            return;
        }

        if self.sanctum_handle.unwrap().0 != null_mut() {
            if let Err(e) = unsafe { CloseServiceHandle(self.sanctum_handle.unwrap()) } {
                eprintln!("[-] Unable to close handle after installing service. Error: {e}");
            }
            self.sanctum_handle = None;
        } else {
            eprintln!("[-] Unable to close handle, handle was null!");
        }
    }
}