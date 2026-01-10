use std::fs;
use std::path::Path;
use std::process::Command;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{NSArray, NSError, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode,
    VZFileHandleSerialPortAttachment, VZLinuxBootLoader, VZNATNetworkDeviceAttachment,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceConfiguration,
    VZVirtioConsolePortConfiguration, VZVirtioEntropyDeviceConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
};

const DISK_PATH: &str = "vm-disk.raw";
const CLOUDINIT_PATH: &str = "cloud-init.iso";
const KERNEL_PATH: &str = "vmlinuz";
const INITRD_PATH: &str = "initrd";

const DISK_SIZE_GB: u64 = 20;

fn create_cloud_init_iso() -> Result<(), Box<dyn std::error::Error>> {
    println!("[DEBUG] Creating cloud-init ISO...");
    fs::create_dir_all("cloud-init-data")?;
    println!("[DEBUG] Created cloud-init-data directory");

    let meta_data = r#"instance-id: vibe-vm
local-hostname: vibe-vm
"#;

    let user_data = r#"#cloud-config
users:
  - name: root
    lock_passwd: false
    hashed_passwd: $6$rounds=4096$salt$JDfoobarhashedpasswordforviberoot
  - name: vibe
    shell: /bin/bash
    lock_passwd: true
    sudo: []

chpasswd:
  list: |
    root:viberoot
  expire: false

write_files:
  - path: /root/provision.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      echo "Provisioning started at $(date)"
      apt-get update
      apt-get install -y curl git build-essential
      echo "Provisioning complete"

runcmd:
  - /root/provision.sh
"#;

    fs::write("cloud-init-data/meta-data", meta_data)?;
    fs::write("cloud-init-data/user-data", user_data)?;
    println!("[DEBUG] Wrote meta-data and user-data files");

    let cloudinit_path = std::path::Path::new(CLOUDINIT_PATH);
    if cloudinit_path.exists() {
        println!("[DEBUG] Removing existing cloud-init ISO");
        std::fs::remove_file(cloudinit_path)?;
    }

    println!("[DEBUG] Running hdiutil to create ISO...");
    let output = Command::new("hdiutil")
        .args([
            "makehybrid",
            "-iso",
            "-joliet",
            "-o",
            CLOUDINIT_PATH,
            "cloud-init-data/",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "[DEBUG] hdiutil stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("Failed to create cloud-init ISO".into());
    }
    println!("[DEBUG] hdiutil completed successfully");

    fs::remove_dir_all("cloud-init-data")?;
    println!("[DEBUG] Cleaned up cloud-init-data directory");
    Ok(())
}

fn create_disk_image() -> Result<(), Box<dyn std::error::Error>> {
    println!("[DEBUG] Checking disk image...");
    if Path::new(DISK_PATH).exists() {
        println!("[DEBUG] Disk image already exists at {}", DISK_PATH);
        return Ok(());
    }

    let size_bytes = DISK_SIZE_GB * 1024 * 1024 * 1024;
    println!("[DEBUG] Creating disk image: {} bytes", size_bytes);
    let file = fs::File::create(DISK_PATH)?;
    file.set_len(size_bytes)?;
    println!("[DEBUG] Disk image created successfully");

    Ok(())
}

fn download_kernel_and_initrd() -> Result<(), Box<dyn std::error::Error>> {
    println!("[DEBUG] Checking for kernel and initrd...");
    if !Path::new(KERNEL_PATH).exists() || !Path::new(INITRD_PATH).exists() {
        eprintln!("You need to provide {} and {}", KERNEL_PATH, INITRD_PATH);
        eprintln!("Extract from a Debian/Ubuntu cloud image or netboot:");
        eprintln!("  wget http://archive.ubuntu.com/ubuntu/dists/noble/main/installer-arm64/current/legacy-images/netboot/ubuntu-installer/arm64/linux -O vmlinuz");
        eprintln!("  wget http://archive.ubuntu.com/ubuntu/dists/noble/main/installer-arm64/current/legacy-images/netboot/ubuntu-installer/arm64/initrd.gz -O initrd");
        return Err("Missing kernel/initrd".into());
    }
    println!(
        "[DEBUG] Kernel path exists: {}",
        Path::new(KERNEL_PATH).exists()
    );
    println!(
        "[DEBUG] Initrd path exists: {}",
        Path::new(INITRD_PATH).exists()
    );

    let kernel_metadata = fs::metadata(KERNEL_PATH)?;
    let initrd_metadata = fs::metadata(INITRD_PATH)?;
    println!("[DEBUG] Kernel size: {} bytes", kernel_metadata.len());
    println!("[DEBUG] Initrd size: {} bytes", initrd_metadata.len());

    Ok(())
}

fn create_vm_configuration(
) -> Result<Retained<VZVirtualMachineConfiguration>, Box<dyn std::error::Error>> {
    println!("[DEBUG] Starting VM configuration creation...");
    unsafe {
        let config = VZVirtualMachineConfiguration::new();
        println!("[DEBUG] Created VZVirtualMachineConfiguration");

        config.setCPUCount(2);
        config.setMemorySize(4 * 1024 * 1024 * 1024);
        println!("[DEBUG] Set CPU count: 2, Memory: 4GB");

        let kernel_path_abs = std::fs::canonicalize(KERNEL_PATH)?;
        println!("[DEBUG] Kernel absolute path: {:?}", kernel_path_abs);
        let kernel_url =
            NSURL::fileURLWithPath(&NSString::from_str(kernel_path_abs.to_str().unwrap()));
        println!("[DEBUG] Created kernel URL");

        let boot_loader =
            VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url);
        println!("[DEBUG] Created boot loader");

        let initrd_path_abs = std::fs::canonicalize(INITRD_PATH)?;
        println!("[DEBUG] Initrd absolute path: {:?}", initrd_path_abs);
        let initrd_url =
            NSURL::fileURLWithPath(&NSString::from_str(initrd_path_abs.to_str().unwrap()));
        boot_loader.setInitialRamdiskURL(Some(&initrd_url));
        println!("[DEBUG] Set initial ramdisk");

        let cmdline =
            NSString::from_str("console=hvc0 root=/dev/vda1 rw earlyprintk=serial");

        boot_loader.setCommandLine(&cmdline);

        config.setBootLoader(Some(&boot_loader));
        println!("[DEBUG] Set boot loader on config");

        let disk_path_abs = std::fs::canonicalize(DISK_PATH)?;
        println!("[DEBUG] Disk absolute path: {:?}", disk_path_abs);
        let disk_url = NSURL::fileURLWithPath(&NSString::from_str(disk_path_abs.to_str().unwrap()));
        println!("[DEBUG] Creating disk attachment...");
        let disk_attachment = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &disk_url,
            false,
            VZDiskImageCachingMode::Automatic,
            VZDiskImageSynchronizationMode::Full
        )?;
        println!("[DEBUG] Created disk attachment");

        let disk_device = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &disk_attachment,
        );
        println!("[DEBUG] Created disk device configuration");

        let cloudinit_path_abs = std::fs::canonicalize(CLOUDINIT_PATH)?;
        println!("[DEBUG] Cloud-init absolute path: {:?}", cloudinit_path_abs);
        let cloudinit_url =
            NSURL::fileURLWithPath(&NSString::from_str(cloudinit_path_abs.to_str().unwrap()));
        println!("[DEBUG] Creating cloud-init attachment...");
        let cloudinit_attachment = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &cloudinit_url,
            true,
            VZDiskImageCachingMode::Automatic,
            VZDiskImageSynchronizationMode::Full
        )?;
        println!("[DEBUG] Created cloud-init attachment");

        let cloudinit_device = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &cloudinit_attachment,
        );
        println!("[DEBUG] Created cloud-init device configuration");

        let storage_devices: Retained<NSArray<_>> = NSArray::from_retained_slice(&[
            Retained::into_super(disk_device),
            Retained::into_super(cloudinit_device),
        ]);
        config.setStorageDevices(&storage_devices);
        println!("[DEBUG] Set storage devices");

        let nat_attachment = VZNATNetworkDeviceAttachment::new();
        let network_device = VZVirtioNetworkDeviceConfiguration::new();
        network_device.setAttachment(Some(&nat_attachment));

        let network_devices: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(network_device)]);
        config.setNetworkDevices(&network_devices);
        println!("[DEBUG] Set network devices");

        let entropy_device = VZVirtioEntropyDeviceConfiguration::new();
        let entropy_devices: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(entropy_device)]);
        config.setEntropyDevices(&entropy_devices);
        println!("[DEBUG] Set entropy devices");

        let stdin_handle = objc2_foundation::NSFileHandle::fileHandleWithStandardInput();
        let stdout_handle = objc2_foundation::NSFileHandle::fileHandleWithStandardOutput();
        println!("[DEBUG] Got file handles for stdin/stdout");

        let serial_attachment =
            VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                VZFileHandleSerialPortAttachment::alloc(),
                Some(&stdin_handle),
                Some(&stdout_handle),
            );
        println!("[DEBUG] Created serial attachment");

        let console_port = VZVirtioConsolePortConfiguration::new();
        console_port.setAttachment(Some(&serial_attachment));

        let console_device = VZVirtioConsoleDeviceConfiguration::new();
        let ports_array = console_device.ports();
        ports_array.setObject_atIndexedSubscript(Some(&console_port), 0);
        println!("[DEBUG] Created console device");

        let console_devices: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(console_device)]);
        config.setConsoleDevices(&console_devices);
        println!("[DEBUG] Set console devices");

        println!("[DEBUG] Validating configuration...");
        let valid = config.validateWithError();
        if let Err(e) = valid {
            eprintln!("[DEBUG] Validation failed: {:?}", e);
            return Err(format!("Invalid VM configuration: {:?}", e).into());
        }
        println!("[DEBUG] Configuration validated successfully");

        Ok(config)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Setting up VM resources...");

    download_kernel_and_initrd()?;
    create_disk_image()?;
    create_cloud_init_iso()?;

    println!("Creating VM configuration...");
    let config = create_vm_configuration()?;

    println!("Initializing virtual machine...");

    println!("[DEBUG] Creating dispatch queue...");
    //let queue = dispatch2::DispatchQueue::new("vm.queue", dispatch2::DispatchQueueAttr::SERIAL);

    let queue = dispatch2::DispatchQueue::main();
    println!("[DEBUG] Dispatch queue created");

    let vm = unsafe {
        println!("[DEBUG] Calling VZVirtualMachine::initWithConfiguration_queue...");
        let vm = VZVirtualMachine::initWithConfiguration_queue(
            VZVirtualMachine::alloc(),
            &config,
            &queue,
        );
        println!("[DEBUG] VZVirtualMachine created");
        vm
    };

    println!("[DEBUG] Checking if VM can start...");
    let can_start = unsafe { vm.canStart() };
    println!("[DEBUG] VM canStart: {}", can_start);

    let initial_state = unsafe { vm.state() };
    println!("[DEBUG] Initial VM state: {:?}", initial_state);

    println!("Starting VM...");

    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();

    let completion_handler = RcBlock::new(move |error: *mut NSError| {
        println!("[DEBUG] Completion handler called");
        if error.is_null() {
            println!("[DEBUG] No error in completion handler");
            let _ = tx.send(Ok(()));
        } else {
            let err = unsafe { &*error };
            let err_desc = unsafe { err.localizedDescription() };
            eprintln!("[DEBUG] Error in completion handler: {:?}", err);
            eprintln!("[DEBUG] Localized description: {:?}", err_desc);

            let _ = tx.send(Err(format!("{:?}", err)));
        }
    });

    println!("[DEBUG] Calling startWithCompletionHandler...");
    unsafe {
        vm.startWithCompletionHandler(&completion_handler);
    }
    println!("[DEBUG] startWithCompletionHandler called, waiting for completion...");

    println!("[DEBUG] Running dispatch main queue to process events...");

    let timeout = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();

    loop {
        let result = unsafe {
            objc2_foundation::NSRunLoop::mainRunLoop().runMode_beforeDate(
                objc2_foundation::NSDefaultRunLoopMode,
                &objc2_foundation::NSDate::distantFuture(),
            )
        };

        match rx.try_recv() {
            Ok(result) => match result {
                Ok(()) => {
                    println!("VM started successfully");
                    break;
                }
                Err(e) => {
                    eprintln!("Failed to start VM: {}", e);
                    return Err(e.into());
                }
            },
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                if start.elapsed() > timeout {
                    eprintln!("[DEBUG] Timeout waiting for VM to start");
                    let state = unsafe { vm.state() };
                    eprintln!("[DEBUG] Current VM state: {:?}", state);
                    return Err("Timeout waiting for VM to start".into());
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                let state = unsafe { vm.state() };
                if start.elapsed().as_secs() % 5 == 0 {
                    println!("[DEBUG] Still waiting... VM state: {:?}", state);
                }
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err("Channel disconnected".into());
            }
        }
    }

    println!("VM is running. Press Ctrl+C to stop.");
    println!("Console output should appear below:");
    println!("---");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));

        let state = unsafe { vm.state() };
        if state != objc2_virtualization::VZVirtualMachineState::Running {
            println!("VM stopped with state: {:?}", state);
            break;
        }
    }

    Ok(())
}
