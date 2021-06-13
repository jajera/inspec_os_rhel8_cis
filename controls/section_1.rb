# controls/section_1.rb
# encoding: UTF-8

control "1.1.1.1_Ensure_mounting_of_cramfs_filesystems_is_disabled" do
  title "Ensure mounting of cramfs filesystems is disabled"
  desc  "
    The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used without having to first decompress the image.
    
    Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the server. If this filesystem type is not needed, disable it.
  "
  impact 1.0
  describe kernel_module('cramfs') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end
end

control "1.1.1.2_Ensure_mounting_of_vFAT_filesystems_is_limited" do
  title "Ensure mounting of vFAT filesystems is limited"
  desc  "
    The vFAT filesystem format is primarily used on older windows systems and portable USB drives or flash modules. It comes in three types FAT12 , FAT16 , and FAT32 all of which are supported by the vfat kernel module.
    
    Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  impact 0.0
  describe kernel_module('vfat') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end
end

control "1.1.1.3_Ensure_mounting_of_squashfs_filesystems_is_disabled" do
  title "Ensure mounting of squashfs filesystems is disabled"
  desc  "
    The squashfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems (similar to cramfs ). A squashfs image can be used without having to first decompress the image.
    
    Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  impact 1.0
  describe kernel_module('squashfs') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end
end

control "1.1.1.4_Ensure_mounting_of_udf_filesystems_is_disabled" do
  title "Ensure mounting of udf filesystems is disabled"
  desc  "
    The udf filesystem type is the universal disk format used to implement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data storage on a broad range of media. This filesystem type is necessary to support writing DVDs and newer optical disc formats.
    
    Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  impact 1.0
  describe kernel_module('udf') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end
end

control "1.1.2_Ensure_tmp_is_configured" do
  title "Ensure /tmp is configured"
  desc  "
    The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.
    
    Rationale: Making /tmp its own file system allows an administrator to set the noexec option on the mount, making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.
    
    This can be accomplished by either mounting tmpfs to /tmp, or creating a separate partition for /tmp.
  "
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
end

control "1.1.3_Ensure_nodev_option_set_on_tmp_partition" do
  title "Ensure nodev option set on /tmp partition"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /tmp .
  "
  impact 1.0
  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control "1.1.4_Ensure_nosuid_option_set_on_tmp_partition" do
  title "Ensure nosuid option set on /tmp partition"
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.
    
    Rationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /tmp .
  "
  impact 1.0
  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control "1.1.5_Ensure_noexec_option_set_on_tmp_partition" do
  title "Ensure noexec option set on /tmp partition"
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.
    
    Rationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /tmp .
  "
  impact 1.0
  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

control "1.1.6_Ensure_separate_partition_exists_for_var" do
  title "Ensure separate partition exists for /var"
  desc  "
    The /var directory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable.
    
    Rationale: Since the /var directory may contain world-writable files and directories, there is a risk of resource exhaustion if it is not bound to a separate partition.
  "
  impact 1.0
  describe mount("/var") do
    it { should be_mounted }
  end
end

control "1.1.7_Ensure_separate_partition_exists_for_vartmp" do
  title "Ensure separate partition exists for /var/tmp"
  desc  "
    The /var/tmp directory is a world-writable directory used for temporary storage by all users and some applications.
    
    Rationale: Since the /var/tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /var/tmp its own file system allows an administrator to set the noexec option on the mount, making /var/tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.
  "
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
end

control "1.1.8_Ensure_nodev_option_set_on_vartmp_partition" do
  title "Ensure nodev option set on /var/tmp partition"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /var/tmp .
  "
  impact 1.0
  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control "1.1.9_Ensure_nosuid_option_set_on_vartmp_partition" do
  title "Ensure nosuid option set on /var/tmp partition"
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.
    
    Rationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /var/tmp .
  "
  impact 1.0
  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control "1.1.10_Ensure_noexec_option_set_on_vartmp_partition" do
  title "Ensure noexec option set on /var/tmp partition"
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.
    
    Rationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /var/tmp .
  "
  impact 1.0
  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

control "1.1.11_Ensure_separate_partition_exists_for_varlog" do
  title "Ensure separate partition exists for /var/log"
  desc  "
    The /var/log directory is used by system services to store log data .
    
    Rationale: There are two important reasons to ensure that system logs are stored on a separate partition: protection against resource exhaustion (since logs can grow quite large) and protection of audit data.
  "
  impact 1.0
  describe mount("/var/log") do
    it { should be_mounted }
  end
end

control "1.1.12_Ensure_separate_partition_exists_for_varlogaudit" do
  title "Ensure separate partition exists for /var/log/audit"
  desc  "
    The auditing daemon, auditd , stores log data in the /var/log/audit directory.
    
    Rationale: There are two important reasons to ensure that data gathered by auditd is stored on a separate partition: protection against resource exhaustion (since the audit.log file can grow quite large) and protection of audit data. The audit daemon calculates how much free space is left and performs actions based on the results. If other processes (such as syslog ) consume space in the same partition as auditd , it may not perform as desired.
  "
  impact 1.0
  describe mount("/var/log/audit") do
    it { should be_mounted }
  end
end

control "1.1.13_Ensure_separate_partition_exists_for_home" do
  title "Ensure separate partition exists for /home"
  desc  "
    The /home directory is used to support disk storage needs of local users.
    
    Rationale: If the system is intended to support local users, create a separate partition for the /home directory to protect against resource exhaustion and restrict the type of files that can be stored under /home .
  "
  impact 1.0
  describe mount("/home") do
    it { should be_mounted }
  end
end

control "1.1.14_Ensure_nodev_option_set_on_home_partition" do
  title "Ensure nodev option set on /home partition"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Since the user partitions are not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices.
  "
  impact 1.0
  describe mount('/home') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control "1.1.15_Ensure_nodev_option_set_on_devshm_partition" do
  title "Ensure nodev option set on /dev/shm partition"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Since the /dev/shm filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in /dev/shm partitions.
  "
  impact 1.0
  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control "1.1.16_Ensure_nosuid_option_set_on_devshm_partition" do
  title "Ensure nosuid option set on /dev/shm partition"
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.
    
    Rationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them.
  "
  impact 1.0
  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control "1.1.17_Ensure_noexec_option_set_on_devshm_partition" do
  title "Ensure noexec option set on /dev/shm partition"
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.
    
    Rationale: Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system.
  "
  impact 1.0
  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

control "1.1.18_Ensure_nodev_option_set_on_removable_media_partitions" do
  title "Ensure nodev option set on removable media partitions"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Removable media containing character and block special devices could be used to circumvent security controls by allowing non-root users to access sensitive device files such as /dev/kmem or the raw disk partitions.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "1.1.19_Ensure_nosuid_option_set_on_removable_media_partitions" do
  title "Ensure nosuid option set on removable media partitions"
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.
    
    Rationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "1.1.20_Ensure_noexec_option_set_on_removable_media_partitions" do
  title "Ensure noexec option set on removable media partitions"
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.
    
    Rationale: Setting this option on a file system prevents users from executing programs from the removable media. This deters users from being able to introduce potentially malicious software on the system.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "1.1.21_Ensure_sticky_bit_is_set_on_all_world-writable_directories" do
  title "Ensure sticky bit is set on all world-writable directories"
  desc  "
    Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.
    
    Rationale: This feature prevents the ability to delete or rename files in world writable directories (such as /tmp ) that are owned by another user.
  "
  impact 1.0
  describe command('find / -path /proc -prune -o -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null') do
    its('stdout') { should be_empty }
    its('exit_status') { should eq 0 }
  end
end

control "1.1.22_Disable_Automounting" do
  title "Disable Automounting"
  desc  "
    autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.
    
    Rationale: With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents available in system even if they lacked permissions to mount it themselves.
  "
  impact 1.0
  describe service('autofs') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end

control "1.1.23_Disable_USB_Storage" do
  title "Disable USB Storage"
  desc  "
    USB storage provides a means to transfer and store files insuring persistence and availability of the files independent of network connection status.  Its popularity and utility has led to USB-based malware being a simple and common means for network infiltration and a first step to establishing a persistent threat within a networked environment.
    
    Rationale: Restricting USB access on the system will decrease the physical attack surface for a device and diminish the possible vectors to introduce malware.
  "
  impact 1.0
  a = command("modprobe -n -v usb-storage").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^usb-storage\s+/) }
    end
  end
  a = command("modprobe -n -v usb-storage").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
end

control "1.2.1_Ensure_Red_Hat_Subscription_Manager_connection_is_configured" do
  title "Ensure Red Hat Subscription Manager connection is configured"
  desc  "
    Systems need to be registered with the Red Hat Subscription Manager (RHSM) to receive patch updates. This is usually configured during initial installation.
    
    Rationale: It is important to register with the Red Hat Subscription Manager to make sure that patches are updated on a regular basis. This helps to reduce the exposure time as new vulnerabilities are discovered.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "1.2.2_Disable_the_rhnsd_Daemon" do
  title "Disable the rhnsd Daemon"
  desc  "
    The rhnsd daemon polls the Red Hat Network web site for scheduled actions and, if there are, executes those actions.
    
    Rationale: Patch management policies may require that organizations test the impact of a patch before it is deployed in a production environment. Having patches automatically deployed could have a negative impact on the environment. It is best to not allow an action by default but only after appropriate consideration has been made. It is recommended that the service be disabled unless the risk is understood and accepted or you are running your own satellite . This item is not scored because organizations may have addressed the risk.
  "
  impact 0.0
  describe service("rhnsd") do
    it { should_not be_enabled }
  end
end

control "1.2.3_Ensure_GPG_keys_are_configured" do
  title "Ensure GPG keys are configured"
  desc  "
    Most packages managers implement GPG key signing to verify package integrity during installation.
    
    Rationale: It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "1.2.4_Ensure_gpgcheck_is_globally_activated" do
  title "Ensure gpgcheck is globally activated"
  desc  "
    The gpgcheck option, found in the main section of the /etc/yum.conf and individual /etc/yum/repos.d/* files determines if an RPM package's signature is checked prior to its installation.
    
    Rationale: It is important to ensure that an RPM's package signature is always checked prior to installation to ensure that the software is obtained from a trusted source.
  "
  impact 1.0
  files = command("find /etc/yum.repos.d/ -type f -regex .\\*/.\\*").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content =~ /^\s*gpgcheck\s*=\s*1\s*(\s+#.*)?$/ || file(f).content !~ /^\s*gpgcheck\s*=\s*[0-9]+\s*(\s+#.*)?$/ } do
    it { should be_empty }
  end
  describe file("/etc/yum.conf") do
    its("content") { should match(/^\s*gpgcheck\s*=\s*1\s*(\s+#.*)?$/) }
  end
  describe file("/etc/yum.conf") do
    its("content") { should_not match(/^\s*gpgcheck\s*=\s*[^1]\s*(\s+#.*)?$/) }
  end
end

control "1.2.5_Ensure_package_manager_repositories_are_configured" do
  title "Ensure package manager repositories are configured"
  desc  "
    Systems need to have package manager repositories configured to ensure they receive the latest patches and updates.
    
    Rationale: If a system's package repositories are misconfigured important patches may not be identified or a rogue repository could introduce compromised software.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "1.3.1_Ensure_sudo_is_installed" do
  title "Ensure sudo is installed"
  desc  "
    sudo allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.  The invoking user's real (not effective) user ID is used to determine the user name with which to query the security policy.
    
    Rationale: sudo supports a plugin architecture for security policies and input/output logging.  Third parties can develop and distribute their own policy and I/O logging plugins to work seamlessly with the sudo front end.  The default security policy is sudoers, which is configured via the file /etc/sudoers.
    
    The security policy determines what privileges, if any, a user has to run sudo.  The policy may require that users authenticate themselves with a password or another authentication mechanism.  If authentication is required, sudo will exit if the user's password is not entered within a configurable time limit.  This limit is policy-specific.
  "
  impact 1.0
  describe package("sudo") do
    it { should be_installed }
  end
end

control "1.3.2_Ensure_sudo_commands_use_pty" do
  title "Ensure sudo commands use pty"
  desc  "
    sudo can be configured to run only from a psuedo-pty
    
    Rationale: Attackers can run a malicious program using sudo which would fork a background process that remains even when the main program has finished executing.
  "
  impact 1.0
  describe.one do
    describe file("/etc/sudoers") do
      its("content") { should match(/^(?i)\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$/) }
    end
    files = command("find /etc/sudoers.d/ -type f -regex .\\*/\\^.\\+\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^(?i)\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$/ } do
      it { should_not be_empty }
    end
  end
end

control "1.3.3_Ensure_sudo_log_file_exists" do
  title "Ensure sudo log file exists"
  desc  "
    sudo can use a custom log file
    
    Rationale: A sudo log file simplifies auditing of sudo commands
  "
  impact 1.0
  describe.one do
    describe file("/etc/sudoers") do
      its("content") { should match(/^(?i)\s*Defaults\s+([^#]+,\s*)?logfile="\S+"(,\s+\S+\s*)*(\s+#.*)?$/) }
    end
    files = command("find /etc/sudoers.d/ -type f -regex .\\*/\\^.\\+\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^(?i)\s*Defaults\s+([^#]+,\s*)?logfile="\S+"(,\s+\S+\s*)*(\s+#.*)?$/ } do
      it { should_not be_empty }
    end
  end
end

control "1.4.1_Ensure_AIDE_is_installed" do
  title "Ensure AIDE is installed"
  desc  "
    AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes which can then be used to compare against the current state of the filesystem to detect modifications to the system.
    
    Rationale: By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure of accidental or malicious misconfigurations or modified binaries.
  "
  impact 1.0
  describe package("aide") do
    it { should be_installed }
  end
end

control "1.4.2_Ensure_filesystem_integrity_is_regularly_checked" do
  title "Ensure filesystem integrity is regularly checked"
  desc  "
    Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.
    
    Rationale: Periodic file checking allows the system administrator to determine on a regular basis if critical files have been changed in an unauthorized fashion.
  "
  impact 1.0
  if service('aidecheck.service').enabled? && service('aidecheck.timer').enabled?
    describe service('aidecheck.service') do
      it { should be_enabled }
    end
    describe service('aidecheck.timer') do
      it { should be_enabled }
    end
  else
    describe.one do
      describe crontab do
        its('commands') { should include '/usr/sbin/aide --check' }
      end
      crontab_path = ['/etc/cron.hourly/', '/etc/cron.daily/', '/etc/cron.weekly/', '/etc/cron.monthly/', '/etc/cron.d/']
      all_cron_files = Hash.new
      crontab_path.map { |path| all_cron_files[path] = command("ls #{path}").stdout.split("\n") }
      all_cron_files.each do |cron_path, cron_files|
        unless cron_files.empty?
          cron_files.each do |cron_file|
            temp = file(cron_path+cron_file)
            describe temp do
              its('content') { should include 'aide --check'}
            end
          end
        end
      end
    end
  end
end

control "1.5.1_Ensure_permissions_on_bootloader_config_are_configured" do
  title "Ensure permissions on bootloader config are configured"
  desc  "
    The grub configuration file contains information on boot settings and passwords for unlocking boot options.
    
    The grub configuration is usually grub.cfg and grubenv stored in /boot/grub2/`
    
    Rationale: Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them.
  "
  impact 1.0
  describe file("/boot/grub2/grub.cfg") do
    it { should exist }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_executable.by "group" }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_readable.by "group" }
  end
  describe file("/boot/grub2/grub.cfg") do
    its("gid") { should cmp 0 }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_writable.by "group" }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_executable.by "other" }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_readable.by "other" }
  end
  describe file("/boot/grub2/grub.cfg") do
    it { should_not be_writable.by "other" }
  end
  describe file("/boot/grub2/grub.cfg") do
    its("uid") { should cmp 0 }
  end
  describe file("/boot/grub2/grubenv") do
    it { should exist }
  end
  describe file("/boot/grub2/grubenv") do
    it { should_not be_executable.by "group" }
  end
  describe file("/boot/grub2/grubenv") do
    it { should_not be_readable.by "group" }
  end
  describe file("/boot/grub2/grubenv") do
    its("gid") { should cmp 0 }
  end
  describe file("/boot/grub2/grubenv") do
    it { should_not be_writable.by "group" }
  end
  describe file("/boot/grub2/grubenv") do
    it { should_not be_executable.by "other" }
  end
  describe file("/boot/grub2/grubenv") do
    it { should_not be_readable.by "other" }
  end
  describe file("/boot/grub2/grubenv") do
    it { should_not be_writable.by "other" }
  end
  describe file("/boot/grub2/grubenv") do
    its("uid") { should cmp 0 }
  end
end

control "1.5.2_Ensure_bootloader_password_is_set" do
  title "Ensure bootloader password is set"
  desc  "
    Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters
    
    Rationale: Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time).
  "
  impact 1.0
  describe file("/boot/grub2/user.cfg") do
    its("content") { should match(/^\s*GRUB2_PASSWORD\s*=\s*.+$/) }
  end
end

control "1.5.3_Ensure_authentication_required_for_single_user_mode" do
  title "Ensure authentication required for single user mode"
  desc  "
    Single user mode (rescue mode) is used for recovery when the system detects an issue during boot or by manual selection from the bootloader.
    
    Rationale: Requiring authentication in single user mode (rescue mode) prevents an unauthorized user from rebooting the system into single user to gain root privileges without credentials.
  "
  impact 1.0
  describe file("/usr/lib/systemd/system/emergency.service") do
    its("content") { should match(/^\s*ExecStart=-\/usr\/lib\/systemd\/systemd-sulogin-shell(\s+emergency|\s*)\s*(\s+#.*)?$/) }
  end
  describe file("/usr/lib/systemd/system/rescue.service") do
    its("content") { should match(/^\s*ExecStart=-\/usr\/lib\/systemd\/systemd-sulogin-shell(\s+rescue\s*|\s*)\s*(\s+#.*)?$/) }
  end
end

control "1.6.1_Ensure_core_dumps_are_restricted" do
  title "Ensure core dumps are restricted"
  desc  "
    A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.
    
    Rationale: Setting a hard limit on core dumps prevents users from overriding the soft variable. If core dumps are required, consider setting limits for user groups (see limits.conf(5) ). In addition, setting the fs.suid_dumpable variable to 0 will prevent setuid programs from dumping core.
  "
  impact 1.0
  describe.one do
    describe file("/etc/security/limits.conf") do
      its("content") { should match(/^\s*\*\s+hard\s+core\s+0\s*(\s+#.*)?$/) }
    end
    files = command("find /etc/security/limits.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*\*\s+hard\s+core\s+0\s*(\s+#.*)?$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("fs.suid_dumpable") do
    its("value") { should_not be_nil }
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*fs\.suid_dumpable\s*=\s*0\s*(\s+#.*)?$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*fs\.suid_dumpable\s*=\s*0\s*(\s+#.*)?$/ } do
      it { should_not be_empty }
    end
  end
end

control "1.6.2_Ensure_address_space_layout_randomization_ASLR_is_enabled" do
  title "Ensure address space layout randomization (ASLR) is enabled"
  desc  "
    Address space layout randomization (ASLR) is an exploit mitigation technique which randomly arranges the address space of key data areas of a process.
    
    Rationale: Randomly placing virtual memory regions will make it difficult to write memory page exploits as the memory placement will be consistently shifting.
  "
  impact 1.0
  describe kernel_parameter("kernel.randomize_va_space") do
    its("value") { should eq 2 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*kernel.randomize_va_space\s*=\s*2$/) }
    end
    files = command("find /etc/sysctl.d/ -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content =~ /^\s*kernel.randomize_va_space\s*=\s*2\s*(\s+#.*)?$/ || file(f).content !~ /^\s*kernel.randomize_va_space\s*=\s*[0-9]+\s*(\s+#.*)?$/ } do
      it { should be_empty }
    end
    files = command("find /usr/lib/sysctl.d/ -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content =~ /^\s*kernel.randomize_va_space\s*=\s*2\s*(\s+#.*)?$/ || file(f).content !~ /^\s*kernel.randomize_va_space\s*=\s*[0-9]+\s*(\s+#.*)?$/ } do
      it { should be_empty }
    end
    files = command("find /run/sysctl.d/ -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content =~ /^\s*kernel.randomize_va_space\s*=\s*2\s*(\s+#.*)?$/ || file(f).content !~ /^\s*kernel.randomize_va_space\s*=\s*[0-9]+\s*(\s+#.*)?$/ } do
      it { should be_empty }
    end
  end
end

control "1.7.1.1_Ensure_SELinux_is_installed" do
  title "Ensure SELinux is installed"
  desc  "
    SELinux provides Mandatory Access Control.
    
    Rationale: Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available.
  "
  impact 1.0
  describe package("libselinux") do
    it { should be_installed }
  end
end

control "1.7.1.2_Ensure_SELinux_is_not_disabled_in_bootloader_configuration" do
  title "Ensure SELinux is not disabled in bootloader configuration"
  desc  "
    Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters.
    
    Rationale: SELinux must be enabled at boot time in your grub configuration to ensure that the controls it provides are not overridden.
  "
  impact 1.0
  describe file("/boot/grub2/grubenv") do
    its("content") { should_not match(/^\s*kernelopts=(\S+\s+)*selinux=0\s*(\S+\s*)*$/) }
  end
  describe file("/boot/grub2/grubenv") do
    its("content") { should_not match(/^\s*kernelopts=(\S+\s+)*enforcing=0\s*(\S+\s*)*$/) }
  end
end

control "1.7.1.3_Ensure_SELinux_policy_is_configured" do
  title "Ensure SELinux policy is configured"
  desc  "
    Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.
    
    Rationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that at least the default recommendations are met.
  "
  impact 1.0
  describe file('/etc/selinux/config') do
    its('content') { should match(/^\s*SELINUXTYPE\s*=\s*(targeted|mls)\s*(\s+#.*)?$/) }
  end
  describe command('sestatus') do
    its('stdout') { should match(/^Loaded\s+policy\s+name:\s+(targeted|mls)\s*(\s+#.*)?$/) }
    its('exit_status') { should eq 0 }
  end
end

control "1.7.1.4_Ensure_the_SELinux_state_is_enforcing" do
  title "Ensure the SELinux state is enforcing"
  desc  "
    Set SELinux to enable when the system is booted.
    
    Rationale: SELinux must be enabled at boot time to ensure that the controls it provides are in effect at all times.
  "
  impact 1.0
  describe file("/etc/selinux/config") do
    its("content") { should match(/^\s*SELINUX\s*=\s*enforcing\s*(\s+#.*)?$/) }
  end
  describe command('sestatus') do
    its('stdout') { should match(/^SELinux status:\s+enabled$/) }
    its('stdout') { should match(/^Current mode:\s+enforcing$/) }
    its('stdout') { should match(/^Mode from config file:\s+enforcing$/) }
    its('exit_status') { should eq 0 }
  end
end

control "1.7.1.5_Ensure_no_unconfined_services_exist" do
  title "Ensure no unconfined services exist"
  desc  "
    Unconfined processes run in unconfined domains
    
    Rationale: For unconfined processes, SELinux policy rules are applied, but policy rules exist that allow processes running in unconfined domains almost all access. Processes running in unconfined domains fall back to using DAC rules exclusively. If an unconfined process is compromised, SELinux does not prevent an attacker from gaining access to system resources and data, but of course, DAC rules are still used. SELinux is a security enhancement on top of DAC rules &#x2013; it does not replace them
  "
  impact 1.0
  processes(/.*/).where { pid > 0 }.raw_data.each do |entry|
    describe entry.label.to_s.split(":")[2] do
      it { should_not cmp "initrc_t" }
    end
  end
end

control "1.7.1.6_Ensure_SETroubleshoot_is_not_installed" do
  title "Ensure SETroubleshoot is not installed"
  desc  "
    The SETroubleshoot service notifies desktop users of SELinux denials through a user-friendly interface. The service provides important information around configuration errors, unauthorized intrusions, and other potential errors.
    
    Rationale: The SETroubleshoot service is an unnecessary daemon to have running on a server, especially if X Windows is disabled.
  "
  impact 1.0
  describe package("setroubleshoot") do
    it { should_not be_installed }
  end
end

control "1.7.1.7_Ensure_the_MCS_Translation_Service_mcstrans_is_not_installed" do
  title "Ensure the MCS Translation Service (mcstrans) is not installed"
  desc  "
    The mcstransd daemon provides category label information to client processes requesting information. The label translations are defined in /etc/selinux/targeted/setrans.conf
    
    Rationale: Since this service is not used very often, remove it to reduce the amount of potentially vulnerable code running on the system.
  "
  impact 1.0
  describe package("mcstrans") do
    it { should_not be_installed }
  end
end

control "1.8.1.1_Ensure_message_of_the_day_is_configured_properly" do
  title "Ensure message of the day is configured properly"
  desc  "
    The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.
    
    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \\m - machine architecture \\r - operating system release \\s - operating system name \\v - operating system version
    
    Rationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" uname -a \" command once they have logged in.
  "
  impact 1.0
  describe file('/etc/motd') do
    its('content') { should_not match(/(\\\v|\\\r|\\\m|\\\s|[Rr][Hh][Ee][Ll])/) }
  end
end

control "1.8.1.2_Ensure_local_login_warning_banner_is_configured_properly" do
  title "Ensure local login warning banner is configured properly"
  desc  "
    The contents of the /etc/issue file are displayed to users prior to login for local terminals.
    
    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \\m - machine architecture \\r - operating system release \\s - operating system name \\v - operating system version - or the operating system's name
    
    Rationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" uname -a \" command once they have logged in.
  "
  impact 1.0
  describe file('/etc/issue') do
    its('content') { should_not match(/(\\\v|\\\r|\\\m|\\\s|[Rr][Hh][Ee][Ll])/) }
  end
end

control "1.8.1.3_Ensure_remote_login_warning_banner_is_configured_properly" do
  title "Ensure remote login warning banner is configured properly"
  desc  "
    The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.
    
    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \\m - machine architecture \\r - operating system release \\s - operating system name \\v - operating system version
    
    Rationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" uname -a \" command once they have logged in.
  "
  impact 1.0
  describe file('/etc/issue.net') do
    its('content') { should_not match(/(\\\v|\\\r|\\\m|\\\s|[Rr][Hh][Ee][Ll])/) }
  end
end

control "1.8.1.4_Ensure_permissions_on_etcmotd_are_configured" do
  title "Ensure permissions on /etc/motd are configured"
  desc  "
    The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.
    
    Rationale: If the /etc/motd file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information.
  "
  impact 1.0
  describe file("/etc/motd") do
    it { should exist }
    it { should_not be_executable.by "group" }
    it { should be_readable.by "group" }
    its("gid") { should cmp 0 }
    it { should_not be_writable.by "group" }
    it { should_not be_executable.by "other" }
    it { should be_readable.by "other" }
    it { should_not be_writable.by "other" }
    it { should_not be_setgid }
    it { should_not be_sticky }
    it { should_not be_setuid }
    it { should_not be_executable.by "owner" }
    it { should be_readable.by "owner" }
    its("uid") { should cmp 0 }
    it { should be_writable.by "owner" }
  end
end

control "1.8.1.5_Ensure_permissions_on_etcissue_are_configured" do
  title "Ensure permissions on /etc/issue are configured"
  desc  "
    The contents of the /etc/issue file are displayed to users prior to login for local terminals.
    
    Rationale: If the /etc/issue file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information.
  "
  impact 1.0
  describe file("/etc/issue") do
    it { should exist }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/issue") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/issue") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/issue") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/issue") do
    it { should_not be_setgid }
  end
  describe file("/etc/issue") do
    it { should_not be_sticky }
  end
  describe file("/etc/issue") do
    it { should_not be_setuid }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/issue") do
    its("uid") { should cmp 0 }
  end
end

control "1.8.1.6_Ensure_permissions_on_etcissue.net_are_configured" do
  title "Ensure permissions on /etc/issue.net are configured"
  desc  "
    The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.
    
    Rationale: If the /etc/issue.net file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information.
  "
  impact 1.0
  describe file("/etc/issue.net") do
    it { should exist }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/issue.net") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/issue.net") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_setgid }
  end
  describe file("/etc/issue.net") do
    it { should_not be_sticky }
  end
  describe file("/etc/issue.net") do
    it { should_not be_setuid }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/issue.net") do
    its("uid") { should cmp 0 }
  end
end

control "1.8.2_Ensure_GDM_login_banner_is_configured" do
  title "Ensure GDM login banner is configured"
  desc  "
    GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.
    
    Rationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place.
  "
  impact 1.0
  describe.one do
    describe file('/etc/gdm/greeter.dconf-defaults') do
      it { should exist }
      its('content') { should match(/^\[org\/gnome\/login-screen\]$/) }
      its('content') { should match(/^banner-message-enable=true$/) }
      its('content') { should match(/^banner-message-text='.+'$/) }
    end
    describe package('gdm') do
      it { should_not be_installed }
    end
  end
end

control "1.9_Ensure_updates_patches_and_additional_security_software_are_installed" do
  title "Ensure updates, patches, and additional security software are installed"
  desc  "
    Periodically patches are released for included software either due to security flaws or to include additional functionality.
    
    Rationale: Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected.
  "
  impact 1.0
  describe command('dnf check-update --security') do
    its('stdout') { should include "currently running version" }
    its('exit_status') { should eq 0 }
  end
end

control "1.10_Ensure_system-wide_crypto_policy_is_not_legacy" do
  title "Ensure system-wide crypto policy is not legacy"
  desc  "
    The system-wide crypto-policies followed by the crypto core components allow consistently deprecating and disabling algorithms system-wide.
    
    The individual policy levels (DEFAULT, LEGACY, FUTURE, and FIPS) are included in the crypto-policies(7) package.
    
    Rationale: If the Legacy system-wide crypto policy is selected, it includes support for TLS 1.0, TLS 1.1, and SSH2 protocols or later. The algorithms DSA, 3DES, and RC4 are allowed, while RSA and Diffie-Hellman parameters are accepted if larger than 1023-bits.
    
    These legacy protocols and algorithms can make the system vulnerable to attacks, including those listed in RFC 7457
  "
  impact 1.0
  describe file("/etc/crypto-policies/config") do
    its("content") { should_not match(/^\s*(?i)LEGACY\s*(\s+#.*)?$/) }
  end
end

control "1.11_Ensure_system-wide_crypto_policy_is_FUTURE_or_FIPS" do
  title "Ensure system-wide crypto policy is FUTURE or FIPS"
  desc  "
    The system-wide crypto-policies followed by the crypto core components allow consistently deprecating and disabling algorithms system-wide.
    
    The individual policy levels (DEFAULT, LEGACY, FUTURE, and FIPS) are included in the crypto-policies(7) package.
    
    Rationale: If the Legacy system-wide crypto policy is selected, it includes support for TLS 1.0, TLS 1.1, and SSH2 protocols or later. The algorithms DSA, 3DES, and RC4 are allowed, while RSA and Diffie-Hellman parameters are accepted if larger than 1023-bits.
    
    These legacy protocols and algorithms can make the system vulnerable to attacks, including those listed in RFC 7457
    
    FUTURE: Is a conservative security level that is believed to withstand any near-term future attacks. This level does not
    allow the use of SHA-1 in signature algorithms. The RSA and Diffie-Hellman parameters are accepted if larger than
    3071 bits. The level provides at least 128-bit security
    
    FIPS:  Conforms to the FIPS 140-2 requirements. This policy is used internally by the fips-mode-setup(8) tool which can
    switch the system into the FIPS 140-2 compliance mode. The level provides at least 112-bit security
  "
  impact 1.0
  describe file("/etc/crypto-policies/config") do
    its("content") { should match(/^(?i)\s*(FUTURE|FIPS)\s*(\s+#.*)?$/) }
  end
end
  