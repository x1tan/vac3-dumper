#![allow(deprecated)]

extern crate nix;
extern crate procfs;
extern crate memchr;
extern crate libc;
extern crate signal;


#[macro_use]
extern crate human_panic;

#[macro_use]
extern crate log;
extern crate env_logger;

mod memory;

use std::{thread, time, mem, ptr, fs, process};
use std::fs::File;
use std::io::prelude::*;
use std::time::Instant;


use nix::sys::ptrace;
use nix::sys::ptrace::Request;
use nix::sys::wait::WaitStatus;
use nix::sys::signal::SIGINT;

use signal::trap::Trap;

static PROCESS_NAME: &str = "steam";
static MODULE_NAME: &str = "steamservice.so";

static PATTERN: &str = "55 B9 32 00 00 00 57 56 31 F6 53 89 F0 E8 B9 F2";

fn main() {


    // Setup beautiful panics for user-friendliness and logging
    setup_panic!();
    env_logger::init();

    // Make sure we have root privileges
    if !nix::unistd::geteuid().is_root() {
        eprintln!("[-] No root privileges!");
        return;
    }


    println!("[+] VAC3 Dumper started.");

    let process = memory::process::Process::new(PROCESS_NAME);
    let mut pid = 0;


    // Setup extra watchdog thread which exists the tool on SIGINT (e.g. ctrl-c)
    let trap = Trap::trap(&[SIGINT]);

    thread::spawn(move || {
        while Some(SIGINT) != trap.wait(Instant::now()) {
            let ten_millis = time::Duration::from_millis(10);
            thread::sleep(ten_millis);
        }


        println!("[*] Shutdown. Make sure to restart Steam and the game!");
        process::exit(0x0100);
    });

    match process {
        Some(p) => {
            println!("[+] Steam process found: {}", p.pid);

            // Grab the steamservice.so module
            let module = match p.modules.iter().find(|x| x.module_name == MODULE_NAME.to_string()) {
                Some(module) => { module }
                None => {
                    panic!("[-] Could not find {}", MODULE_NAME);
                }
            };

            // Find the address of the ELF loader function
            let elf_loader = module.start_address + match p.find_pattern(MODULE_NAME.to_string(), PATTERN.to_string()) {
                Some(elf_loader) => { elf_loader }
                None => {
                    panic!("[-] Could not find ELF Loader function");
                }
            };

            println!("[+] ELF Loader found: 0x{:x}", elf_loader as u64);


            // Wait for steam to spawn the thread which is used for manually loading the shared library
            loop {
                let paths = fs::read_dir(format!("/proc/{}/task", p.pid)).unwrap();


                for path in paths {
                    let dir = path.unwrap();
                    let mut path_buffer = dir.path();
                    path_buffer.push("status");
                    let mut f = match File::open(path_buffer) {
                        Ok(f) => { f },
                        Err(_e) => { continue; }
                    };

                    let mut contents = String::new();
                    f.read_to_string(&mut contents)
                        .expect("something went wrong reading the file");

                    // The thread which calls the ELF loader function has a specific name
                    if contents.contains("ClientModuleMan") {
                        let folder = dir.file_name();
                        let name = folder.to_str().unwrap();
                        pid = String::from(name).parse::<i32>().unwrap();
                    }
                }

                if pid != 0 {
                    println!("[+] Loader thread found.");
                    break;
                }
            }


            // Attach to thread loader thread
            match ptrace::attach(nix::unistd::Pid::from_raw(pid)) {
                Ok(_r) => {
                    println!("[+] Attached to loader thread.");
                }
                Err(e) => {
                    panic!("[-] Could not attach to process: {}", e);
                }
            }

            // Wait  for stop signal to be sure we are attached
            match nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None) {
                Ok(_wait_status) => {}
                Err(e) => {
                    panic!("[-] Could not wait for process: {}", e);
                }
            }

            // Create backup of current function start
            let mut backup_data = unsafe {
                match nix::sys::ptrace::ptrace(Request::PTRACE_PEEKTEXT, nix::unistd::Pid::from_raw(pid), elf_loader as *mut nix::libc::c_void, ptr::null_mut()) {
                    Ok(backup_data) => { backup_data }
                    Err(e) => {
                        panic!("[-] Could not peektext: {}", e);
                    }
                }
            };

            debug!("[+] Original data: 0x{:x}", backup_data);

            // Insert breakpoint (int 3) into the current instructions
            let int3 = 0xCC;
            let data_with_trap = (backup_data & 0xFFFFFF00) | int3;

            // Write edited data back to the function start
            unsafe {
                match nix::sys::ptrace::ptrace(Request::PTRACE_POKETEXT, nix::unistd::Pid::from_raw(pid), elf_loader as *mut nix::libc::c_void, data_with_trap as *mut nix::libc::c_void) {
                    Err(e) => {
                        panic!("[-] Could not poketxt: {}", e);
                    }
                    _ => {}
                }
            };

            // Reread the function start so check if software interrupt instruction (int 3) was placed correctly
            let mut new_data = unsafe {
                match nix::sys::ptrace::ptrace(Request::PTRACE_PEEKTEXT, nix::unistd::Pid::from_raw(pid), elf_loader as *mut nix::libc::c_void, ptr::null_mut()) {
                    Ok(new_data) => { new_data }
                    Err(e) => {
                        panic!("[-] Could not peektext: {}", e);
                    }
                }
            };

            debug!("[+] Replaced data: 0x{:x}", new_data);

            match ptrace::cont(nix::unistd::Pid::from_raw(pid), None) {
                Err(e) => {
                    panic!("[-] Could not continue process: {}", e);
                }
                _ => {}
            }

            // We want to do this in a loop because there are typically multiple modules loaded during
            // the runtime of the game.
            loop {

                // Wait for the loader thread to hit our breakpoint
                match nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None) {
                    Ok(wait_status) => {
                        match wait_status {
                            WaitStatus::Stopped(_pid, signal) => {
                                debug!("[+] Traced process was stopped/trapped! Signal: {:?}", signal);
                            }
                            WaitStatus::Signaled(_pid, signal, _dumped) => {
                                panic!("[-] Traced process was terminated! Signal:{:?}", signal);
                            }
                            _ => {
                                panic!("[-] Traced process was <unknown>");
                            }
                        }
                    }
                    Err(e) => {
                        panic!("[-] Could not wait for process: {}", e);
                    }
                }

                let mut registers: libc::user_regs_struct;
                registers = unsafe { mem::uninitialized() };
                registers.rip = 0;

                // Read the current registers
                unsafe {
                    match nix::sys::ptrace::ptrace(Request::PTRACE_GETREGS, nix::unistd::Pid::from_raw(pid), ptr::null_mut(), std::mem::transmute::<&libc::user_regs_struct, *mut libc::c_void>(&registers)) {
                        Err(e) => {
                            panic!("[-] Could not poketxt: {}", e);
                        }
                        _ => {}
                    }
                };

                // There is no way the instruction pointer is currently at 0x0
                assert_ne!(registers.rip, 0);

                // Check if instruction pointer is where we expect it to be (start of function + 1)
                if registers.rip == (elf_loader + 1) {
                    debug!("[+] Thread {} at bp!", pid);
                    debug!("[+] RIP: 0x{:x}", registers.rip);

                    // Size of the buffer which contains the module is the first function argument (stackpointer + 12)
                    let size = unsafe {
                        match nix::sys::ptrace::ptrace(Request::PTRACE_PEEKTEXT, nix::unistd::Pid::from_raw(pid), (registers.rsp + 12) as *mut nix::libc::c_void, ptr::null_mut()) {
                            Ok(new_data) => { new_data as u32 }
                            Err(e) => {
                                panic!("[-] Could not peektext: {}", e);
                            }
                        }
                    };

                    // Pointer to buffer which contains the module is the second function argument (stackpointer + 8)
                    let buffer = unsafe {
                        match nix::sys::ptrace::ptrace(Request::PTRACE_PEEKTEXT, nix::unistd::Pid::from_raw(pid), (registers.rsp + 8) as *mut nix::libc::c_void, ptr::null_mut()) {
                            Ok(new_data) => { new_data as u32 }
                            Err(e) => {
                                panic!("[-] Could not peektext: {}", e);
                            }
                        }
                    };


                    let mut buffer_data = vec![];

                    // Read the buffer which contains the module (a single byte per read)
                    for n in 0..size {
                        let chunk = unsafe {
                            match nix::sys::ptrace::ptrace(Request::PTRACE_PEEKTEXT, nix::unistd::Pid::from_raw(pid), (buffer + n) as *mut nix::libc::c_void, ptr::null_mut()) {
                                Ok(new_data) => { new_data as u8 }
                                Err(e) => {
                                    panic!("[-] Could not peektext: {}", e);
                                }
                            }
                        };

                        buffer_data.push(chunk);
                    }

                    // Save the module (<size>.so) to disk
                    let mut f = File::create(format!("{}.so", size)).expect("Unable to create file");
                    let _ = f.write_all(&buffer_data);

                    println!("[+] New module loaded and dumped: {}.so [0x{:x}, {:x}]", size, buffer, size);

                    // Restore the original function start because we need to be able to run this function correctly
                    // to load the VAC3 module correctly
                    unsafe {
                        match nix::sys::ptrace::ptrace(Request::PTRACE_POKETEXT, nix::unistd::Pid::from_raw(pid), elf_loader as *mut nix::libc::c_void, backup_data as *mut nix::libc::c_void) {
                            Err(e) => {
                                panic!("[-] Could not poketext: {}", e);
                            }
                            _ => {}
                        }
                    };

                    // Instruction pointer needs to go one step backwards (because currently it points to start of the function + 1)
                    registers.rip -= 1;

                    // Write edited registers back (we edited rip)
                    unsafe {
                        match nix::sys::ptrace::ptrace(Request::PTRACE_SETREGS, nix::unistd::Pid::from_raw(pid), ptr::null_mut(), std::mem::transmute::<&libc::user_regs_struct, *mut libc::c_void>(&registers)) {
                            Err(e) => {
                                panic!("[-] Could not setregs: {}", e);
                            }
                            _ => {}
                        }
                    };

                    // Step over the next 5 instructions
                    for _ in 0..5 {

                        // Step a single instruction
                        match ptrace::step(nix::unistd::Pid::from_raw(pid), None) {
                            Err(e) => {
                                panic!("[-] Could not single step: {}", e);
                            }
                            _ => {}
                        }

                        // Wait for stop signal
                        match nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None) {
                            Ok(wait_status) => {
                                match wait_status {
                                    WaitStatus::Stopped(_pid, signal) => {
                                        debug!("[+] Traced process was stopped/trapped! Signal: {:?}", signal);
                                    }
                                    WaitStatus::Signaled(_pid, signal, _dumped) => {
                                        panic!("[-] Traced process was terminated! Signal:{:?}", signal);
                                    }
                                    _ => {
                                        panic!("[-] Traced process was <unknown>");
                                    }
                                }
                            }
                            Err(e) => {
                                panic!("[-] Could not wait for process: {}", e);
                            }
                        }
                    }

                    // We are now at function start + 5 and can safely write our breakpoint back to the function start
                    // to be able to break the next time the loader function gets called (for the next module)
                    unsafe {
                        match nix::sys::ptrace::ptrace(Request::PTRACE_POKETEXT, nix::unistd::Pid::from_raw(pid), elf_loader as *mut nix::libc::c_void, data_with_trap as *mut nix::libc::c_void) {
                            Err(e) => {
                                panic!("[-] Could not poketxt: {}", e);
                            }
                            Ok(_r) => {
                                debug!("[+] Poketext");
                            }
                        }
                    };
                }

                // Continue and wait for next breakpoint to be hit
                match ptrace::cont(nix::unistd::Pid::from_raw(pid), None) {
                    Err(e) => {
                        panic!("[-] Could not continue process: {}", e);
                    }
                    Ok(_r) => {
                        debug!("[+] Continue");
                    }
                }
            }
        }
        None => {
            eprintln!("[-] Steam process not found. Please start Steam!");
        }
    }
}
