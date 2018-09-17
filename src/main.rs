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
    setup_panic!();
    env_logger::init();

    if !nix::unistd::geteuid().is_root() {
        eprintln!("[-] No root privileges!");
        return;
    }


    println!("[+] VAC3 Dumper started.");

    let process = memory::process::Process::new(PROCESS_NAME);
    let mut pid = 0;


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

            let module = match p.modules.iter().find(|x| x.module_name == MODULE_NAME.to_string()) {
                Some(module) => { module }
                None => {
                    panic!("[-] Could not find {}", MODULE_NAME);
                }
            };

            let elf_loader = module.start_address + match p.find_pattern(MODULE_NAME.to_string(), PATTERN.to_string()) {
                Some(elf_loader) => { elf_loader }
                None => {
                    panic!("[-] Could not find ELF Loader function");
                }
            };

            println!("[+] ELF Loader found: 0x{:x}", elf_loader as u64);


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


            // Attach the process

            match ptrace::attach(nix::unistd::Pid::from_raw(pid)) {
                Ok(_r) => {
                    println!("[+] Attached to loader thread.");
                }
                Err(e) => {
                    panic!("[-] Could not attach to process: {}", e);
                }
            }

            match nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None) {
                Ok(_wait_status) => {}
                Err(e) => {
                    panic!("[-] Could not wait for process: {}", e);
                }
            }


            let mut backup_data = unsafe {
                match nix::sys::ptrace::ptrace(Request::PTRACE_PEEKTEXT, nix::unistd::Pid::from_raw(pid), elf_loader as *mut nix::libc::c_void, ptr::null_mut()) {
                    Ok(backup_data) => { backup_data }
                    Err(e) => {
                        panic!("[-] Could not peektext: {}", e);
                    }
                }
            };

            debug!("[+] Original data: 0x{:x}", backup_data);

            let int3 = 0xCC;

            let data_with_trap = (backup_data & 0xFFFFFF00) | int3;

            unsafe {
                match nix::sys::ptrace::ptrace(Request::PTRACE_POKETEXT, nix::unistd::Pid::from_raw(pid), elf_loader as *mut nix::libc::c_void, data_with_trap as *mut nix::libc::c_void) {
                    Err(e) => {
                        panic!("[-] Could not poketxt: {}", e);
                    }
                    _ => {}
                }
            };


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

            loop {
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

                unsafe {
                    match nix::sys::ptrace::ptrace(Request::PTRACE_GETREGS, nix::unistd::Pid::from_raw(pid), ptr::null_mut(), std::mem::transmute::<&libc::user_regs_struct, *mut libc::c_void>(&registers)) {
                        Err(e) => {
                            panic!("[-] Could not poketxt: {}", e);
                        }
                        _ => {}
                    }
                };


                assert_ne!(registers.rip, 0);

                if registers.rip == (elf_loader + 1) {
                    debug!("[+] Thread {} at bp!", pid);
                    debug!("[+] RIP: 0x{:x}", registers.rip);


                    let size = unsafe {
                        match nix::sys::ptrace::ptrace(Request::PTRACE_PEEKTEXT, nix::unistd::Pid::from_raw(pid), (registers.rsp + 12) as *mut nix::libc::c_void, ptr::null_mut()) {
                            Ok(new_data) => { new_data as u32 }
                            Err(e) => {
                                panic!("[-] Could not peektext: {}", e);
                            }
                        }
                    };

                    let buffer = unsafe {
                        match nix::sys::ptrace::ptrace(Request::PTRACE_PEEKTEXT, nix::unistd::Pid::from_raw(pid), (registers.rsp + 8) as *mut nix::libc::c_void, ptr::null_mut()) {
                            Ok(new_data) => { new_data as u32 }
                            Err(e) => {
                                panic!("[-] Could not peektext: {}", e);
                            }
                        }
                    };


                    let mut buffer_data = vec![];

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

                    let mut f = File::create(format!("{}.so", size)).expect("Unable to create file");
                    let _ = f.write_all(&buffer_data);

                    println!("[+] New module loaded and dumped: {}.so [0x{:x}, {:x}]", size, buffer, size);


                    unsafe {
                        match nix::sys::ptrace::ptrace(Request::PTRACE_POKETEXT, nix::unistd::Pid::from_raw(pid), elf_loader as *mut nix::libc::c_void, backup_data as *mut nix::libc::c_void) {
                            Err(e) => {
                                panic!("[-] Could not poketext: {}", e);
                            }
                            _ => {}
                        }
                    };

                    registers.rip -= 1;


                    unsafe {
                        match nix::sys::ptrace::ptrace(Request::PTRACE_SETREGS, nix::unistd::Pid::from_raw(pid), ptr::null_mut(), std::mem::transmute::<&libc::user_regs_struct, *mut libc::c_void>(&registers)) {
                            Err(e) => {
                                panic!("[-] Could not setregs: {}", e);
                            }
                            _ => {}
                        }
                    };

                    for _ in 0..5 {
                        match ptrace::step(nix::unistd::Pid::from_raw(pid), None) {
                            Err(e) => {
                                panic!("[-] Could not single step: {}", e);
                            }
                            _ => {}
                        }


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
