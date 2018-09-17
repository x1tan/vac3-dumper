pub mod process {
    use procfs;
    use nix;
    use memchr::memchr;

    use std::u8;


    #[derive(Clone, Debug)]
    pub struct Module {
        pub module_name: String,
        pub start_address: u64,
        pub end_address: u64,
        pub size: u64,
    }

    #[derive(Clone, Debug)]
    pub struct Process {
        pub process_name: String,
        pub base_address: u64,
        pub pid: i32,
        pub modules: Vec<Module>,
    }

    impl Process {
        pub fn new(process_name: &str) -> Option<Process> {
            for process in procfs::all_processes() {
                let path_result = process.exe();

                match path_result {
                    procfs::ProcResult::Ok(path) => {
                        let file_name = path.as_path().file_name().unwrap().to_str().unwrap();

                        if file_name == process_name {
                            let modules = _retrieve_modules(process.maps().unwrap());

                            let process = Process {
                                process_name: file_name.to_string(),
                                base_address: modules[0].start_address,
                                pid: process.pid(),
                                modules,
                            };

                            return Some(process);
                        }
                    }
                    _ => {}
                }
            }

            None
        }

        #[allow(dead_code)]
        pub fn is_running(&self) -> bool {
            match nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(self.pid))) {
                Ok(_pid) => {
                    return true;
                }
                Err(_e) => {
                    return false;
                }
            }
        }

        pub fn find_pattern(&self, module_name: String, pattern: String) -> Option<u64> {
            let module = match self.modules.iter().find(|x| x.module_name == module_name) {
                Some(module) => { module }
                None => {
                    return None;
                }
            };


            let mut module_buffer: Vec<u8> = vec![0; module.size as usize];

            let bytes_read = self.read_bytes(module.start_address, module.size, module_buffer.as_mut_slice());

            if bytes_read == 0 {
                eprintln!("[-] Could not copy module.");
                return None;
            }


            // Parse our pattern

            let mut pattern_parsed = vec![];

            for sub in pattern.split_whitespace() {
                if sub == "??" {
                    pattern_parsed.push('?' as u8);
                } else {
                    let hex = match u8::from_str_radix(sub, 16) {
                        Ok(hex) => { hex }
                        Err(e) => {
                            eprintln!("[-] Could not parse pattern: {}", e);
                            return None;
                        }
                    };

                    pattern_parsed.push(hex);
                }
            }

            let mut shifted_index = 0;

            loop {
                match memchr(pattern_parsed[0], &module_buffer) {
                    Some(index) => {
                        let mut pattern_found = true;

                        for (i, byte) in pattern_parsed.iter().enumerate() {
                            if *byte == '?' as u8 {
                                continue;
                            }

                            if module_buffer[index + i] != *byte {
                                pattern_found = false;
                                break;
                            }
                        }

                        if pattern_found {
                            return Some((shifted_index + index) as u64);
                        } else {
                            module_buffer.drain(0..index + 1);
                            shifted_index = shifted_index + index + 1;
                        }
                    }
                    None => {
                        break;
                    }
                }
            }


            None
        }

        pub fn read_bytes(&self, address: u64, size: u64, buffer: &mut [u8]) -> usize {
            let io_vec = [nix::sys::uio::IoVec::from_mut_slice(buffer)];

            let remote_io_vec = [nix::sys::uio::RemoteIoVec {
                base: address as usize,
                len: size as usize,
            }];

            match nix::sys::uio::process_vm_readv(nix::unistd::Pid::from_raw(self.pid), &io_vec, &remote_io_vec) {
                Ok(bytes_read) => { bytes_read }
                Err(_err) => { 0 }
            }
        }
    }

    fn _retrieve_modules(map: Vec<procfs::MemoryMap>) -> Vec<Module> {
        let mut modules: Vec<Module> = Vec::new();

        for memory_region in map {
            match memory_region.pathname {
                procfs::MMapPath::Path(path) => {
                    let file_name = path.file_name().unwrap().to_os_string().into_string().unwrap();

                    let mut existing_module = -1;

                    for (i, module) in modules.iter().enumerate() {
                        if module.module_name == file_name {
                            existing_module = i as i32;
                        }
                    }

                    if existing_module >= 0 {
                        let index = existing_module as usize;

                        modules[index].end_address = memory_region.address.1;
                        modules[index].size = modules[index].end_address - modules[index].start_address;
                    } else {
                        let module = Module {
                            module_name: file_name,
                            start_address: memory_region.address.0,
                            end_address: memory_region.address.1,
                            size: memory_region.address.1 - memory_region.address.0,
                        };

                        modules.push(module);
                    }
                }
                _ => {}
            };
        }


        modules
    }
}