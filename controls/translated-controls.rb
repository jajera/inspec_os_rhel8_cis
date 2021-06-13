# encoding: UTF-8

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.1_Ensure_mounting_of_cramfs_filesystems_is_disabled" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.2_Ensure_mounting_of_vFAT_filesystems_is_limited" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.3_Ensure_mounting_of_squashfs_filesystems_is_disabled" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.4_Ensure_mounting_of_udf_filesystems_is_disabled" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.2_Ensure_tmp_is_configured" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.3_Ensure_nodev_option_set_on_tmp_partition" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.4_Ensure_nosuid_option_set_on_tmp_partition" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.5_Ensure_noexec_option_set_on_tmp_partition" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.6_Ensure_separate_partition_exists_for_var" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.7_Ensure_separate_partition_exists_for_vartmp" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.8_Ensure_nodev_option_set_on_vartmp_partition" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.9_Ensure_nosuid_option_set_on_vartmp_partition" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.10_Ensure_noexec_option_set_on_vartmp_partition" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.11_Ensure_separate_partition_exists_for_varlog" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.12_Ensure_separate_partition_exists_for_varlogaudit" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.13_Ensure_separate_partition_exists_for_home" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.14_Ensure_nodev_option_set_on_home_partition" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.15_Ensure_nodev_option_set_on_devshm_partition" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.16_Ensure_nosuid_option_set_on_devshm_partition" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.17_Ensure_noexec_option_set_on_devshm_partition" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.18_Ensure_nodev_option_set_on_removable_media_partitions" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.19_Ensure_nosuid_option_set_on_removable_media_partitions" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.20_Ensure_noexec_option_set_on_removable_media_partitions" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.21_Ensure_sticky_bit_is_set_on_all_world-writable_directories" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.22_Disable_Automounting" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.23_Disable_USB_Storage" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.2.1_Ensure_Red_Hat_Subscription_Manager_connection_is_configured" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.2.2_Disable_the_rhnsd_Daemon" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.2.3_Ensure_GPG_keys_are_configured" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.2.4_Ensure_gpgcheck_is_globally_activated" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.2.5_Ensure_package_manager_repositories_are_configured" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.3.1_Ensure_sudo_is_installed" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.3.2_Ensure_sudo_commands_use_pty" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.3.3_Ensure_sudo_log_file_exists" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.4.1_Ensure_AIDE_is_installed" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.4.2_Ensure_filesystem_integrity_is_regularly_checked" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.5.1_Ensure_permissions_on_bootloader_config_are_configured" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.5.2_Ensure_bootloader_password_is_set" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.5.3_Ensure_authentication_required_for_single_user_mode" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.6.1_Ensure_core_dumps_are_restricted" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.6.2_Ensure_address_space_layout_randomization_ASLR_is_enabled" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.1_Ensure_SELinux_is_installed" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.2_Ensure_SELinux_is_not_disabled_in_bootloader_configuration" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.3_Ensure_SELinux_policy_is_configured" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.4_Ensure_the_SELinux_state_is_enforcing" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.5_Ensure_no_unconfined_services_exist" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.6_Ensure_SETroubleshoot_is_not_installed" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.7.1.7_Ensure_the_MCS_Translation_Service_mcstrans_is_not_installed" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.8.1.1_Ensure_message_of_the_day_is_configured_properly" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.8.1.2_Ensure_local_login_warning_banner_is_configured_properly" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.8.1.3_Ensure_remote_login_warning_banner_is_configured_properly" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.8.1.4_Ensure_permissions_on_etcmotd_are_configured" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.8.1.5_Ensure_permissions_on_etcissue_are_configured" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.8.1.6_Ensure_permissions_on_etcissue.net_are_configured" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.8.2_Ensure_GDM_login_banner_is_configured" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.9_Ensure_updates_patches_and_additional_security_software_are_installed" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.10_Ensure_system-wide_crypto_policy_is_not_legacy" do
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

control "xccdf_org.cisecurity.benchmarks_rule_1.11_Ensure_system-wide_crypto_policy_is_FUTURE_or_FIPS" do
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

control "xccdf_org.cisecurity.benchmarks_rule_2.1.1_Ensure_xinetd_is_not_installed" do
  title "Ensure xinetd is not installed"
  desc  "
    The eXtended InterNET Daemon ( xinetd ) is an open source super daemon that replaced the original inetd daemon. The xinetd daemon listens for well known services and dispatches the appropriate daemon to properly respond to service requests.
    
    Rationale: If there are no xinetd services required, it is recommended that the package be removed.
  "
  impact 1.0
  describe package("xinetd") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.1.1_Ensure_time_synchronization_is_in_use" do
  title "Ensure time synchronization is in use"
  desc  "
    System time should be synchronized between all systems in an environment. This is typically done by establishing an authoritative time server or set of servers and having all systems synchronize their clocks to them.
    
    Rationale: Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log files have consistent time records across the enterprise, which aids in forensic investigations.
  "
  impact 0.0
  describe package("chrony") do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.1.2_Ensure_chrony_is_configured" do
  title "Ensure chrony is configured"
  desc  "
    chrony is a daemon which implements the Network Time Protocol (NTP) and is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on chrony can be found at [http://chrony.tuxfamily.org/](http://chrony.tuxfamily.org/) . chrony can be configured to be a client and/or a server.
    
    Rationale: If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working properly.
    
    This recommendation only applies if chrony is in use on the system.
  "
  impact 1.0
  if package('chrony').installed?
    describe file('/etc/chrony.conf') do
      its('content') { should match(/^\s*(server|pool)\s+\S+/) }
    end
    opts = ini('/etc/sysconfig/chronyd').params['OPTIONS'] || []
    if opts.include?('-u chrony')
      describe ini('/etc/sysconfig/chronyd') do
        its('OPTIONS') { should include '-u chrony' }
      end
    else
      describe ini('/usr/lib/systemd/system/chronyd.service') do
        its(['Service', 'ExecStart']) { should include '-u chrony' }
      end
    end
  else
    describe package('chrony') do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.2_Ensure_X_Window_System_is_not_installed" do
  title "Ensure X Window System is not installed"
  desc  "
    The X Window System provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Windows system is typically used on workstations where users login, but not on servers where users typically do not login.
    
    Rationale: Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface.
  "
  impact 1.0
  describe packages(/^xorg-x11.*/) do
    its("entries") { should be_empty }
  end
  describe packages(/^xserver-xorg.*/) do
    its("entries") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.3_Ensure_rsync_service_is_not_enabled" do
  title "Ensure rsync service is not enabled"
  desc  "
    The rsyncd service can be used to synchronize files between systems over network links.
    
    Rationale: The rsyncd service presents a security risk as it uses unencrypted protocols for communication.
  "
  impact 1.0
  describe service('rsyncd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.4_Ensure_Avahi_Server_is_not_enabled" do
  title "Ensure Avahi Server is not enabled"
  desc  "
    Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine.
    
    Rationale: Automatic discovery of network services is not normally required for system functionality. It is recommended to disable the service to reduce the potential attack surface.
  "
  impact 1.0
  describe service('avahi-daemon') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.5_Ensure_SNMP_Server_is_not_enabled" do
  title "Ensure SNMP Server is not enabled"
  desc  "
    The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system.
    
    Rationale: The SNMP server can communicate using SNMP v1, which transmits data in the clear and does not require authentication to execute commands.  Unless absolutely necessary, it is recommended that the SNMP service not be used.  If SNMP is required the server should be configured to disallow SNMP v1.
  "
  impact 1.0
  describe service('snmpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.6_Ensure_HTTP_Proxy_Server_is_not_enabled" do
  title "Ensure HTTP Proxy Server is not enabled"
  desc  "
    Squid is a standard proxy server used in many distributions and environments.
    
    Rationale: If there is no need for a proxy server, it is recommended that the squid proxy be deleted to reduce the potential attack surface.
  "
  impact 1.0
  describe service('squid') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.7_Ensure_Samba_is_not_enabled" do
  title "Ensure Samba is not enabled"
  desc  "
    The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Server Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems.
    
    Rationale: If there is no need to mount directories and file systems to Windows systems, then this service can be deleted to reduce the potential attack surface.
  "
  impact 1.0
  describe service('smb') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.8_Ensure_IMAP_and_POP3_server_is_not_enabled" do
  title "Ensure IMAP and POP3 server is not enabled"
  desc  "
    dovecot is an open source IMAP and POP3 server for Linux based systems.
    
    Rationale: Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the service be deleted to reduce the potential attack surface.
  "
  impact 1.0
  describe service('dovecot') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.9_Ensure_HTTP_server_is_not_enabled" do
  title "Ensure HTTP server is not enabled"
  desc  "
    HTTP or web servers provide the ability to host web site content.
    
    Rationale: Unless there is a need to run the system as a web server, it is recommended that the package be deleted to reduce the potential attack surface.
  "
  impact 1.0
  describe service('httpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.10_Ensure_FTP_Server_is_not_enabled" do
  title "Ensure FTP Server is not enabled"
  desc  "
    The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.
    
    Rationale: FTP does not protect the confidentiality of data or authentication credentials. It is recommended SFTP be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be deleted to reduce the potential attack surface.
  "
  impact 1.0
  describe service('vsftpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.11_Ensure_DNS_Server_is_not_enabled" do
  title "Ensure DNS Server is not enabled"
  desc  "
    The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network.
    
    Rationale: Unless a system is specifically designated to act as a DNS server, it is recommended that the package be deleted to reduce the potential attack surface.
  "
  impact 1.0
  describe service('named') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.12_Ensure_NFS_is_not_enabled" do
  title "Ensure NFS is not enabled"
  desc  "
    The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.
    
    Rationale: If the system does not export NFS shares, it is recommended that the NFS be disabled to reduce the remote attack surface.
  "
  impact 1.0
  describe service('nfs') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.13_Ensure__RPC_is_not_enabled" do
  title "Ensure  RPC is not enabled"
  desc  "
    The rpcbind service maps Remote Procedure Call (RPC) services to the ports on which they listen. RPC
    processes notify rpcbind when they start, registering the ports they are listening on and the RPC
    program numbers they expect to serve. The client system then contacts rpcbind on the server with a
    particular RPC program number. The rpcbind service redirects the client to the proper port number so it
    can communicate with the requested service.
    
    Rationale: If the system does not require rpc based services, it is recommended that rpcbind be disabled to reduce the remote attack surface.
  "
  impact 1.0
  describe service('rpcbind') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.14_Ensure_LDAP_server_is_not_enabled" do
  title "Ensure LDAP server is not enabled"
  desc  "
    The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.
    
    Rationale: If the system will not need to act as an LDAP server, it is recommended that the software be disabled to reduce the potential attack surface.
  "
  impact 1.0
  describe service('slapd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.15_Ensure_DHCP_Server_is_not_enabled" do
  title "Ensure DHCP Server is not enabled"
  desc  "
    The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses.
    
    Rationale: Unless a system is specifically set up to act as a DHCP server, it is recommended that this service be deleted to reduce the potential attack surface.
  "
  impact 1.0
  describe service('dhcpd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.16_Ensure_CUPS_is_not_enabled" do
  title "Ensure CUPS is not enabled"
  desc  "
    The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability.
    
    Rationale: If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be disabled to reduce the potential attack surface.
  "
  impact 1.0
  describe service('cups') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.17_Ensure_NIS_Server_is_not_enabled" do
  title "Ensure NIS Server is not enabled"
  desc  "
    The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory service protocol for distributing system configuration files. The NIS server is a collection of programs that allow for the distribution of configuration files.
    
    Rationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be disabled and other, more secure services be used
  "
  impact 1.0
  describe service('ypserv') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.18_Ensure_mail_transfer_agent_is_configured_for_local-only_mode" do
  title "Ensure mail transfer agent is configured for local-only mode"
  desc  "
    Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and transfer the messages to the appropriate user or mail server. If the system is not intended to be a mail server, it is recommended that the MTA be configured to only process local mail.
    
    Rationale: The software for all Mail Transfer Agents is complex and most have a long history of security issues. While it is important to ensure that the system can process local mail messages, it is not necessary to have the MTA's daemon listening on a port unless the server is intended to be a mail server that receives and processes mail from other systems.
  "
  impact 1.0
  describe port(25).where { protocol =~ /.*/ && address =~ /^(?!127\.0\.0\.1|::1).*$/ } do
    its("entries") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.1_Ensure_NIS_Client_is_not_installed" do
  title "Ensure NIS Client is not installed"
  desc  "
    The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client ( ypbind ) was used to bind a machine to an NIS server and receive the distributed configuration files.
    
    Rationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed.
  "
  impact 1.0
  describe package("ypbind") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.2_Ensure_telnet_client_is_not_installed" do
  title "Ensure telnet client is not installed"
  desc  "
    The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol.
    
    Rationale: The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The ssh package provides an encrypted session and stronger security and is included in most Linux distributions.
  "
  impact 1.0
  describe package("telnet") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.3_Ensure_LDAP_client_is_not_installed" do
  title "Ensure LDAP client is not installed"
  desc  "
    The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.
    
    Rationale: If the system will not need to act as an LDAP client, it is recommended that the software be removed to reduce the potential attack surface.
  "
  impact 1.0
  describe package("openldap-clients") do
    it { should_not be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.1.1_Ensure_IP_forwarding_is_disabled" do
  title "Ensure IP forwarding is disabled"
  desc  "
    The net.ipv4.ip_forward and net.ipv6.conf.all.forwarding flags are used to tell the system whether it can forward packets or not.
    
    Rationale: Setting the flags to 0 ensures that a system with multiple interfaces (for example, a hard proxy), will never be able to forward packets, and therefore, never serve as a router.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.ip_forward") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should_not match(/^\s*net.ipv4.ip_forward\s*=\s*1$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.ip_forward\s*=\s*1$/ } do
      it { should be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.ip_forward\s*=\s*1$/ } do
      it { should be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.ip_forward\s*=\s*1$/ } do
      it { should be_empty }
    end
  end
  describe kernel_parameter("net.ipv6.conf.all.forwarding") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should_not match(/^\s*net.ipv6.conf.all.forwarding\s*=\s*1$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.forwarding\s*=\s*1$/ } do
      it { should be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.forwarding\s*=\s*1$/ } do
      it { should be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.forwarding\s*=\s*1$/ } do
      it { should be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.1.2_Ensure_packet_redirect_sending_is_disabled" do
  title "Ensure packet redirect sending is disabled"
  desc  "
    ICMP Redirects are used to send routing information to other hosts. As a host itself does not act as a router (in a host only configuration), there is no need to send redirects.
    
    Rationale: An attacker could use a compromised host to send invalid ICMP redirects to other router devices in an attempt to corrupt routing and have users access a system set up by the attacker as opposed to a valid system.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.send_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.send_redirects") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.all.send_redirects\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.send_redirects\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.default.send_redirects\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.send_redirects\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.1_Ensure_source_routed_packets_are_not_accepted" do
  title "Ensure source routed packets are not accepted"
  desc  "
    In networking, source routing allows a sender to partially or fully specify the route packets take through a network. In contrast, non-source routed packets travel a path determined by routers in the network. In some cases, systems may not be routable or reachable from some locations (e.g. private addresses vs. Internet routable), and so source routed packets would need to be used.
    
    Rationale: Setting net.ipv4.conf.all.accept_source_route, net.ipv4.conf.default.accept_source_route, net.ipv6.conf.all.accept_source_route and net.ipv6.conf.default.accept_source_route to 0 disables the system from accepting source routed packets. Assume this system was capable of routing packets to Internet routable addresses on one interface and private addresses on another interface. Assume that the private addresses were not routable to the Internet routable addresses and vice versa. Under normal routing circumstances, an attacker from the Internet routable addresses could not use the system as a way to reach the private address systems. If, however, source routed packets were allowed, they could be used to gain access to the private address systems as the route could be specified, rather than rely on routing protocols that did not allow this routing.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.all.accept_source_route\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.accept_source_route\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.default.accept_source_route\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.accept_source_route\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv6.conf.all.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv6.conf.all.accept_source_route") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv6.conf.all.accept_source_route\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.accept_source_route\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv6.conf.default.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv6.conf.default.accept_source_route") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv6.conf.default.accept_source_route\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.default.accept_source_route\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.2_Ensure_ICMP_redirects_are_not_accepted" do
  title "Ensure ICMP redirects are not accepted"
  desc  "
    ICMP redirect messages are packets that convey routing information and tell your host (acting as a router) to send packets via an alternate path. It is a way of allowing an outside routing device to update your system routing tables. By setting net.ipv4.conf.all.accept_redirects and net.ipv6.conf.all.accept_redirects to 0, the system will not accept any ICMP redirect messages, and therefore, won't allow outsiders to update the system's routing tables.
    
    Rationale: Attackers could use bogus ICMP redirect messages to maliciously alter the system routing tables and get them to send packets to incorrect networks and allow your system packets to be captured.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.all.accept_redirects\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.accept_redirects\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.all.accept_redirects\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.accept_redirects\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv6.conf.all.accept_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv6.conf.all.accept_redirects") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv6.conf.all.accept_redirects\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.accept_redirects\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv6.conf.default.accept_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv6.conf.default.accept_redirects") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv6.conf.default.accept_redirects\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.default.accept_redirects\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.3_Ensure_secure_ICMP_redirects_are_not_accepted" do
  title "Ensure secure ICMP redirects are not accepted"
  desc  "
    Secure ICMP redirects are the same as ICMP redirects, except they come from gateways listed on the default gateway list. It is assumed that these gateways are known to your system, and that they are likely to be secure.
    
    Rationale: It is still possible for even known gateways to be compromised. Setting net.ipv4.conf.all.secure_redirects to 0 protects the system from routing table updates by possibly compromised known gateways.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.secure_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.secure_redirects") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.all.secure_redirects\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.secure_redirects\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.conf.default.secure_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.secure_redirects") do
    its("value") { should eq 0 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.default.secure_redirects\s*=\s*0$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.secure_redirects\s*=\s*0$/ } do
      it { should_not be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.4_Ensure_suspicious_packets_are_logged" do
  title "Ensure suspicious packets are logged"
  desc  "
    When enabled, this feature logs packets with un-routable source addresses to the kernel log.
    
    Rationale: Enabling this feature and logging these packets allows an administrator to investigate the possibility that an attacker is sending spoofed packets to their system.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its("value") { should eq 1 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.all.log_martians\s*=\s*1$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.log_martians\s*=\s*1$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.conf.default.log_martians") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.log_martians") do
    its("value") { should eq 1 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.default.log_martians\s*=\s*1$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.log_martians\s*=\s*1$/ } do
      it { should_not be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.5_Ensure_broadcast_ICMP_requests_are_ignored" do
  title "Ensure broadcast ICMP requests are ignored"
  desc  "
    Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all ICMP echo and timestamp requests to broadcast and multicast addresses.
    
    Rationale: Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for your network could be used to trick your host into starting (or participating) in a Smurf attack. A Smurf attack relies on an attacker sending large amounts of ICMP broadcast messages with a spoofed source address. All hosts receiving this message and responding would send echo-reply messages back to the spoofed address, which is probably not routable. If many hosts respond to the packets, the amount of traffic on the network could be significantly multiplied.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts") do
    its("value") { should eq 1 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1$/ } do
      it { should_not be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1$/ } do
      it { should_not be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1$/ } do
      it { should_not be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.6_Ensure_bogus_ICMP_responses_are_ignored" do
  title "Ensure bogus ICMP responses are ignored"
  desc  "
    Setting icmp_ignore_bogus_error_responses to 1 prevents the kernel from logging bogus responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from filling up with useless log messages.
    
    Rationale: Some routers (and some attackers) will send responses that violate RFC-1122 and attempt to fill up a log file system with many useless error messages.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses") do
    its("value") { should eq 1 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*1$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*1$/ } do
      it { should_not be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*1$/ } do
      it { should_not be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*1$/ } do
      it { should_not be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.7_Ensure_Reverse_Path_Filtering_is_enabled" do
  title "Ensure Reverse Path Filtering is enabled"
  desc  "
    Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to 1 forces the Linux kernel to utilize reverse path filtering on a received packet to determine if the packet was valid. Essentially, with reverse path filtering, if the return packet does not go out the same interface that the corresponding source packet came from, the packet is dropped (and logged if log_martians is set).
    
    Rationale: Setting these flags is a good way to deter attackers from sending your system bogus packets that cannot be responded to. One instance where this feature breaks down is if asymmetrical routing is employed. This would occur when using dynamic routing protocols (bgp, ospf, etc) on your system. If you are using asymmetrical routing on your system, you will not be able to enable this feature without breaking the routing.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.rp_filter") do
    its("value") { should eq 1 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.conf.all.rp_filter\s*=\s*1$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.rp_filter\s*=\s*1$/ } do
      it { should_not be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.rp_filter\s*=\s*1$/ } do
      it { should_not be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.rp_filter\s*=\s*1$/ } do
      it { should_not be_empty }
    end
  end
  describe kernel_parameter("net.ipv4.conf.default.rp_filter") do
    its("value") { should_not be_nil }
    its("value") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.8_Ensure_TCP_SYN_Cookies_is_enabled" do
  title "Ensure TCP SYN Cookies is enabled"
  desc  "
    When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that encodes the source and destination IP address and port number and the time the packet was sent. A legitimate connection would send the ACK packet of the three way handshake with the specially crafted sequence number. This allows the system to verify that it has received a valid response to a SYN cookie and allow the connection, even though there is no corresponding SYN in the queue.
    
    Rationale: Attackers use SYN flood attacks to perform a denial of service attacked on a system by sending many SYN packets without completing the three way handshake. This will quickly use up slots in the kernel's half-open connection queue and prevent legitimate connections from succeeding. SYN cookies allow the system to keep accepting valid connections, even if under a denial of service attack.
  "
  impact 1.0
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its("value") { should eq 1 }
  end
  describe.one do
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^\s*net.ipv4.tcp_syncookies\s*=\s*1$/) }
    end
    files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.tcp_syncookies\s*=\s*1$/ } do
      it { should_not be_empty }
    end
    files = command("find /usr/lib/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.tcp_syncookies\s*=\s*1$/ } do
      it { should_not be_empty }
    end
    files = command("find /run/sysctl.d -type f -regex .\\*/.\\*").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.tcp_syncookies\s*=\s*1$/ } do
      it { should_not be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.2.9_Ensure_IPv6_router_advertisements_are_not_accepted" do
  title "Ensure IPv6 router advertisements are not accepted"
  desc  "
    This setting disables the system's ability to accept IPv6 router advertisements.
    
    Rationale: It is recommended that systems do not accept router advertisements as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes.
  "
  impact 1.0
  if command("grep '^\\s*kernelopts=\\(\\S\\+\\s\\+\\)*ipv6.disable=1\\b\\s*\\(\\S\\+\\s*\\)*$' /boot/grub2/grubenv").exit_status == 1
    describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
      its('value') { should eq 0 }
    end
    describe kernel_parameter('net.ipv6.conf.default.accept_ra') do
      its('value') { should eq 0 }
    end
    describe.one do
      describe file('/etc/sysctl.conf') do
        its('content') { should match(/^\s*net.ipv6.conf.all.accept_ra\s*=\s*0$/) }
      end
      files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
      describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.accept_ra\s*=\s*0$/ } do
        it { should_not be_empty }
      end
    end
    describe.one do
      describe file('/etc/sysctl.conf') do
        its('content') { should match(/^\s*net.ipv6.conf.default.accept_ra\s*=\s*0$/) }
      end
      files = command("find /etc/sysctl.d -type f -regex .\\*/.\\*").stdout.split
      describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.default.accept_ra\s*=\s*0$/ } do
        it { should_not be_empty }
      end
    end
  else
    describe command ("grep '^\\s*kernelopts=\\(\\S\\+\\s\\+\\)*ipv6.disable=1\\b\\s*\\(\\S\\+\\s*\\)*$' /boot/grub2/grubenv") do
      its('exit_status') { should_not eq 1 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.3.1_Ensure_DCCP_is_disabled" do
  title "Ensure DCCP is disabled"
  desc  "
    The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that supports streaming media and telephony. DCCP provides a way to gain access to congestion control, without having to do it at the application layer, but does not provide in-sequence delivery.
    
    Rationale: If the protocol is not required, it is recommended that the drivers not be installed to reduce the potential attack surface.
  "
  impact 1.0
  describe kernel_module('dccp') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.3.2_Ensure_SCTP_is_disabled" do
  title "Ensure SCTP is disabled"
  desc  "
    The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to support message oriented communication, with several streams of messages in one connection. It serves a similar function as TCP and UDP, incorporating features of both. It is message-oriented like UDP, and ensures reliable in-sequence transport of messages with congestion control like TCP.
    
    Rationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
  "
  impact 1.0
  describe kernel_module('sctp') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.3.3_Ensure_RDS_is_disabled" do
  title "Ensure RDS is disabled"
  desc  "
    The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide low-latency, high-bandwidth communications between cluster nodes. It was developed by the Oracle Corporation.
    
    Rationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
  "
  impact 1.0
  describe kernel_module('rds') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.3.4_Ensure_TIPC_is_disabled" do
  title "Ensure TIPC is disabled"
  desc  "
    The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communication between cluster nodes.
    
    Rationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
  "
  impact 1.0
  describe kernel_module('tipc') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.1.1_Ensure_a_Firewall_package_is_installed" do
  title "Ensure a Firewall package is installed"
  desc  "
    A Firewall package should be selected.  Most firewall configuration utilities operate as a front end to nftables or iptables.
    
    Rationale: A Firewall package  is required for firewall management and configuration.
  "
  impact 1.0
  describe.one do
    describe package("firewalld") do
      it { should be_installed }
    end
    describe package("nftables") do
      it { should be_installed }
    end
    describe package("iptables") do
      it { should be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.2.1_Ensure_firewalld_service_is_enabled_and_running" do
  title "Ensure firewalld service is enabled and running"
  desc  "
    Ensure that the firewalld service is enabled to protect your system
    
    Rationale: firewalld (Dynamic Firewall Manager) tool provides a dynamically managed firewall. The tool enables network/firewall zones to define the trust level of network connections and/or interfaces. It has support both for IPv4 and IPv6 firewall settings. Also, it supports Ethernet bridges and allow you to separate between runtime and permanent configuration options. Finally, it supports an interface for services or applications to add firewall rules directly
  "
  impact 1.0
  describe.one do
    describe service("firewalld") do
      it { should be_enabled }
    end
    describe service("iptables") do
      it { should be_enabled }
    end
    describe service("nftables") do
      it { should be_enabled }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.2.2_Ensure_iptables_is_not_enabled" do
  title "Ensure iptables is not enabled"
  desc  "
    IPtables is an application that allows a system administrator to configure the IPv4 and IPv6 tables, chains and rules provided by the Linux kernel firewall.
    
    IPtables is installed as a dependency with firewalld.
    
    Rationale: Running firewalld and IPtables concurrently may lead to conflict, therefore IPtables should be stopped and masked when using firewalld.
  "
  impact 1.0
  if package('firewalld').installed? && service('firewalld').enabled?
    describe.one do
      describe package('iptables') do
        it { should_not be_installed }
      end
      describe service('iptables') do
        it { should_not be_enabled }
      end
    end
  else
    describe.one do
      describe package('firewalld') do
        it { should_not be_installed }
      end
      describe service('firewalld') do
        it { should_not be_enabled }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.2.3_Ensure_nftables_is_not_enabled" do
  title "Ensure nftables is not enabled"
  desc  "
    nftables is a subsystem of the Linux kernel providing filtering and classification of network packets/datagrams/frames and is the successor to iptables.
    
    nftables are installed as a dependency with firewalld.
    
    Rationale: Running firewalld and nftables concurrently may lead to conflict, therefore nftables should be stopped and masked when using firewalld.
  "
  impact 1.0
  if package('firewalld').installed? && service('firewalld').enabled?
    describe.one do
      describe package('nftables') do
        it { should_not be_installed }
      end
      describe service('nftables') do
        it { should_not be_enabled }
      end
    end
  else
    describe.one do
      describe package('firewalld') do
        it { should_not be_installed }
      end
      describe service('firewalld') do
        it { should_not be_enabled }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.2.4_Ensure_default_zone_is_set" do
  title "Ensure default zone is set"
  desc  "
    A firewall zone defines the trust level for a connection, interface or source address binding. This is a one to many relation, which means that a connection, interface or source can only be part of one zone, but a zone can be used for many network connections, interfaces and sources.
    
    The default zone is the zone that is used for everything that is not explicitely bound/assigned to another zone.
    
    That means that if there is no zone assigned to a connection, interface or source, only the default zone is used. The default zone is not always listed as being used for an interface or source as it will be used for it either way. This depends on the manager of the interfaces.
    
    Connections handled by NetworkManager are listed as NetworkManager requests to add the zone binding for the interface used by the connection. Also interfaces under control of the network service are listed also because the service requests it.
    
    Rationale: Because the default zone is the zone that is used for everything that is not explicitly bound/assigned to another zone, it is important for the default zone to set
  "
  impact 1.0
  describe.one do
    describe file("/etc/firewalld/firewalld.conf") do
      its("content") { should match(/^\s*DefaultZone=\S+/) }
    end
    describe package("firewalld") do
      it { should_not be_installed }
    end
    describe service("firewalld") do
      it { should_not be_enabled }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.2.5_Ensure_network_interfaces_are_assigned_to_appropriate_zone" do
  title "Ensure network interfaces are assigned to appropriate zone"
  desc  "
    firewall zones define the trust level of network connections or interfaces.
    
    Rationale: A network interface not assigned to the appropriate zone can allow unexpected or undesired network traffic to be accepted on the interface
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.2.6_Ensure_unnecessary_services_and_ports_are_not_accepted" do
  title "Ensure unnecessary services and ports are not accepted"
  desc  "
    Services and ports can be accepted or explicitly rejected or dropped by a zone.
    
    For every zone, you can set a default behavior that handles incoming traffic that is not further specified. Such behavior is defined by setting the target of the zone. There are three options - default, ACCEPT, REJECT, and DROP.
    
    By setting the target to ACCEPT, you accept all incoming packets except those disabled by a specific rule.
    
    If you set the target to REJECT or DROP, you disable all incoming packets except those that you have allowed in specific rules. When packets are rejected, the source machine is informed about the rejection, while there is no information sent when the packets are dropped.
    
    Rationale: To reduce the attack surface of a system, all services and ports should be blocked unless required
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.3.1_Ensure_iptables_are_flushed" do
  title "Ensure iptables are flushed"
  desc  "
    nftables is a replacement for iptables, ip6tables, ebtables and arptables
    
    Rationale: It is possible to mix iptables and nftables. However, this increases complexity and also the chance to introduce errors. For simplicity flush out all iptables rules, and ensure it is not loaded
  "
  impact 0.0
  if package('nftables').installed? && service('nftables').enabled? && package('iptables').installed?
    describe command('iptables -L --line-numbers') do
      its('stdout') { should_not match(/^\s*\d/) }
      its('exit_status') { should eq 0 }
    end
    describe command('ip6tables -L --line-numbers') do
      its('stdout') { should_not match(/^\s*\d/) }
      its('exit_status') { should eq 0 }
    end
  else
    describe.one do
      describe package('nftables') do
        it { should_not be_installed }
      end
      describe service('nftables') do
        it { should_not be_enabled }
      end
      describe package('iptables') do
        it { should_not be_installed }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.3.2_Ensure_a_table_exists" do
  title "Ensure a table exists"
  desc  "
    Tables hold chains.  Each table only has one address family and only applies to packets of this family.  Tables can have one of five families.
    
    Rationale: nftables doesn't have any default tables.  Without a table being build, nftables will not filter network traffic.
  "
  impact 1.0
  describe.one do
    describe command('nft list tables') do
      its('stdout') { should match(/^table\s+\S+\s+\S+/) }
      its('exit_status') { should eq 0 }
    end
    describe package('nftables') do
      it { should_not be_installed }
    end
    describe service('nftables') do
      it { should_not be_enabled }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.3.3_Ensure_base_chains_exist" do
  title "Ensure base chains exist"
  desc  "
    Chains are containers for rules. They exist in two kinds, base chains and regular chains. A base chain is an  entry  point  for packets from the networking stack, a regular chain may be used as jump target and is used for better rule organization.
    
    Rationale: If a base chain doesn't exist with a hook for input, forward, and delete, packets that would flow through those chains will not be touched by nftables.
  "
  impact 1.0
  if package('nftables').installed? && service('nftables').enabled?
    describe command('nft list ruleset') do
      its('stdout') { should match(/^\s*\S+\s+\S+\s+hook\s+input/) }
      its('stdout') { should match(/^\s*\S+\s+\S+\s+hook\s+forward/) }
      its('stdout') { should match(/^\s*\S+\s+\S+\s+hook\s+output/) }
      its('exit_status') { should eq 0 }
    end
  else
    describe.one do
      describe package('nftables') do
        it { should_not be_installed }
      end
      describe service('nftables') do
        it { should_not be_enabled }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.3.4_Ensure_loopback_traffic_is_configured" do
  title "Ensure loopback traffic is configured"
  desc  "
    Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network
    
    Rationale: Loopback traffic is generated between processes on a machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure.
  "
  impact 1.0
  if package('nftables').installed? && service('nftables').enabled?
    describe.one do
      describe command("nft list ruleset | awk '/hook input/,/}/' | grep 'iif \"lo\" accept'") do
        its('stdout') { should match(/^\s*iif\s+"lo"\s+accept/) }
        its('exit_status') { should eq 0 }
      end
      describe command("nft list ruleset | awk '/hook input/,/}/' | grep 'ip sddr'") do
        its('stdout') { should match(/^\s*ip\s+saddr\s+127\.0\.0\.0\/8\s+counter\s+packets\s+0\s+bytes\s+0\s+drop/) }
        its('exit_status') { should eq 0 }
      end
    end
    describe.one do
      describe command("nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'") do
        its('stdout') { should match(/^\s*ip6\s+saddr\s+\:\:1\s+counter\s+packets\s+0\s+bytes\s+0\s+drop/) }
        its('exit_status') { should eq 0 }
      end
      describe file("\\boot\\grub2\\grubenv") do
        its("content") { should match(/^\s*kernelopts=(\S+\s+)*ipv6\.disable=1\s*(\S+\s*)*$/) }
      end
    end
  else
    describe.one do
      describe package('nftables') do
        it { should_not be_installed }
      end
      describe service('nftables') do
        it { should_not be_enabled }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.3.5_Ensure_outbound_and_established_connections_are_configured" do
  title "Ensure outbound and established connections are configured"
  desc  "
    Configure the firewall rules for new outbound, and established connections
    
    Rationale: If rules are not in place for new outbound, and established connections all packets will be dropped by the default policy preventing network usage.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.3.6_Ensure_default_deny_firewall_policy" do
  title "Ensure default deny firewall policy"
  desc  "
    Base chain policy is the default verdict that will be applied to packets reaching the end of the chain.
    
    Rationale: There are two policies: accept (Default) and drop.  If the policy is set to accept , the firewall will accept any packet that is not configured to be denied and the packet will continue transversing the network stack.
    
    It is easier to white list acceptable usage than to black list unacceptable usage.
  "
  impact 1.0
  if package('nftables').installed? && service('nftables').enabled?
    describe command("nft list ruleset | grep 'hook input'") do
      its('stdout') { should match(/^.*policy\s*drop;$/) }
      its('exit_status') { should eq 0 }
    end
    describe command("nft list ruleset | grep 'hook forward'") do
      its('stdout') { should match(/^.*policy\s*drop;$/) }
      its('exit_status') { should eq 0 }
    end
    describe command("nft list ruleset | grep 'hook output'") do
      its('stdout') { should match(/^.*policy\s*drop;$/) }
      its('exit_status') { should eq 0 }
    end
  else
    describe.one do
      describe package('nftables') do
        it { should_not be_installed }
      end
      describe service('nftables') do
        it { should_not be_enabled }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.3.7_Ensure_nftables_service_is_enabled" do
  title "Ensure nftables service is enabled"
  desc  "
    The nftables service allows for the loading of nftables rulesets during boot, or starting of the nftables service
    
    Rationale: The nftables service restores the nftables rules from the rules files referenced in the /etc/sysconfig/nftables.conf file durring boot or the starting of the nftables service
  "
  impact 1.0
  describe.one do
    describe service("nftables") do
      it { should be_enabled }
    end
    describe service("firewalld") do
      it { should be_enabled }
    end
    describe service("iptables") do
      it { should be_enabled }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.3.8_Ensure_nftables_rules_are_permanent" do
  title "Ensure nftables rules are permanent"
  desc  "
    nftables is a subsystem of the Linux kernel providing filtering and classification of network packets/datagrams/frames.
    
    The nftables service reads the /etc/sysconfig/nftables.conf file for a nftables file or files to include in the nftables ruleset.
    
    A nftables ruleset containing the input, forward, and output base chains allow network traffic to be filtered.
    
    Rationale: Changes made to nftables ruleset only affect the live system, you will also need to configure the nftables ruleset to apply on boot.
  "
  impact 1.0
  if package('nftables').installed? && service('nftables').enabled?
    describe file("/etc/sysconfig/nftables.conf") do
      its("content") { should match(/^\s*include/) }
    end
  else
    describe.one do
      describe package("nftables") do
        it { should_not be_installed }
      end
      describe service("nftables") do
        it { should_not be_enabled }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.4.1.1_Ensure_default_deny_firewall_policy" do
  title "Ensure default deny firewall policy"
  desc  "
    A default deny all policy on connections ensures that any unconfigured network usage will be rejected.
    
    Rationale: With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage.
  "
  impact 1.0
  if package('iptables').installed? && service('iptables').enabled?
    %w[INPUT OUTPUT FORWARD].each do |chain|
      describe.one do
        describe iptables do
          it { should have_rule("-P #{chain} DROP") }
        end
        describe iptables do
          it { should have_rule("-P #{chain} REJECT") }
        end
      end
    end
  else
    describe.one do
      describe package('iptables') do
        it { should_not be_installed }
      end
      describe service('iptables') do
        it { should_not be_enabled }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.4.1.2_Ensure_loopback_traffic_is_configured" do
  title "Ensure loopback traffic is configured"
  desc  "
    Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network (127.0.0.0/8).
    
    Rationale: Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network (127.0.0.0/8) traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure.
  "
  impact 1.0
  describe.one do
    describe iptables do
      it { should have_rule('-A INPUT -i lo -j ACCEPT') }
      it { should have_rule('-A OUTPUT -o lo -j ACCEPT') }
      it { should have_rule('-A INPUT -s 127.0.0.0/8 -j DROP') }
    end
    describe package('iptables') do
      it { should_not be_installed }
    end
    describe service('iptables') do
      it { should_not be_enabled }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.4.1.3_Ensure_outbound_and_established_connections_are_configured" do
  title "Ensure outbound and established connections are configured"
  desc  "
    Configure the firewall rules for new outbound, and established connections.
    
    Rationale: If rules are not in place for new outbound, and established connections all packets will be dropped by the default policy preventing network usage.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.4.1.4_Ensure_firewall_rules_exist_for_all_open_ports" do
  title "Ensure firewall rules exist for all open ports"
  desc  "
    Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.
    
    Rationale: Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports.
  "
  impact 1.0
  if package('iptables').installed? && service('iptables').enabled?
    port.where { protocol =~ /.*/ && port >= 0 && address =~ /^(?!127\.0\.0\.1|::1|::).*$/ }.entries.each do |entry|
      rule_inbound = "-A INPUT -p #{entry[:protocol]} -m #{entry[:protocol]} --dport #{entry[:port]} -m state --state NEW,ESTABLISHED -j ACCEPT"
      rule_outbound = "-A OUTPUT -p #{entry[:protocol]} -m #{entry[:protocol]} --sport #{entry[:port]} -m state --state ESTABLISHED -j ACCEPT"
      describe iptables do
        it { should have_rule(rule_inbound) }
        it { should have_rule(rule_outbound) }
      end
    end
  else
    describe.one do
      describe package('iptables') do
        it { should_not be_installed }
      end
      describe service('iptables') do
        it { should_not be_enabled }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.4.2.1_Ensure_IPv6_default_deny_firewall_policy" do
  title "Ensure IPv6 default deny firewall policy"
  desc  "
    A default deny all policy on connections ensures that any unconfigured network usage will be rejected.
    
    Rationale: With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage.
  "
  impact 1.0
  if package('iptables').installed? && service('iptables').enabled?
    %w[INPUT OUTPUT FORWARD].each do |chain|
      describe.one do
        describe ip6tables do
          it { should have_rule("-P #{chain} DROP") }
        end
        describe ip6tables do
          it { should have_rule("-P #{chain} REJECT") }
        end
      end
    end
  else
    describe.one do
      describe package('iptables') do
        it { should_not be_installed }
      end
      describe service('iptables') do
        it { should_not be_enabled }
      end
      describe file("/boot/grub2/grubenv") do
        its("content") { should match(/^\s*kernelopts=(\S+\s+)*ipv6\.disable=1\b\s*(\S+\s*)*$/) }
      end
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.4.2.2_Ensure_IPv6_loopback_traffic_is_configured" do
  title "Ensure IPv6 loopback traffic is configured"
  desc  "
    Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network (::1).
    
    Rationale: Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network (::1) traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure.
  "
  impact 1.0
  describe.one do
    describe ip6tables do
      it { should have_rule('-A INPUT -i lo -j ACCEPT') }
      it { should have_rule('-A OUTPUT -o lo -j ACCEPT') }
      it { should have_rule('-A INPUT -s ::1 -j DROP') }
    end
    describe package('iptables') do
      it { should_not be_installed }
    end
    describe service('iptables') do
      it { should_not be_enabled }
    end
    describe file("/boot/grub2/grubenv") do
      its("content") { should match(/^\s*kernelopts=(\S+\s+)*ipv6\.disable=1\b\s*(\S+\s*)*$/) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.4.2.3_Ensure_IPv6_outbound_and_established_connections_are_configured" do
  title "Ensure IPv6 outbound and established connections are configured"
  desc  "
    Configure the firewall rules for new outbound, and established IPv6 connections.
    
    Rationale: If rules are not in place for new outbound, and established connections all packets will be dropped by the default policy preventing network usage.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.4.4.2.4_Ensure_IPv6_firewall_rules_exist_for_all_open_ports" do
  title "Ensure IPv6 firewall rules exist for all open ports"
  desc  "
    Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.
    
    Rationale: Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.5_Ensure_wireless_interfaces_are_disabled" do
  title "Ensure wireless interfaces are disabled"
  desc  "
    Wireless networking is used when wired networks are unavailable. Red Hat Enterprise Linux contains a wireless tool kit to allow system administrators to configure and use wireless networks.
    
    Rationale: If wireless is not to be used, wireless devices can be disabled to reduce the potential attack surface.
  "
  impact 1.0
  describe command('nmcli radio wifi') do
    its('stdout') { should_not match(/enabled/) }
    its('exit_status') { should eq 0 }
  end
  describe command('nmcli radio wwan') do
    its('stdout') { should_not match(/enabled/) }
    its('exit_status') { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_3.6_Disable_IPv6" do
  title "Disable IPv6"
  desc  "
    Although IPv6 has many advantages over IPv4, not all organizations have IPv6 or dual stack configurations implemented.
    
    Rationale: If IPv6 or dual stack is not to be used, it is recommended that IPv6 be disabled to reduce the attack surface of the system.
  "
  impact 0.0
  describe file("/boot/grub2/grubenv") do
    its("content") { should match(/^\s*kernelopts=(\S+\s+)*ipv6\.disable=1\b\s*(\S+\s*)*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.1.1_Ensure_auditd_is_installed" do
  title "Ensure auditd is installed"
  desc  "
    auditd is the userspace component to the Linux Auditing System. It's responsible for writing audit records to the disk
    
    Rationale: The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.
  "
  impact 1.0
  describe package("audit") do
    it { should be_installed }
  end
  describe package("audit-libs") do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.1.2_Ensure_auditd_service_is_enabled" do
  title "Ensure auditd service is enabled"
  desc  "
    Turn on the auditd daemon to record system events.
    
    Rationale: The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.
  "
  impact 1.0
  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.1.3_Ensure_auditing_for_processes_that_start_prior_to_auditd_is_enabled" do
  title "Ensure auditing for processes that start prior to auditd is enabled"
  desc  "
    Configure grub2 so that processes that are capable of being audited can be audited even if they start up prior to auditd startup.
    
    Rationale: Audit events need to be captured on processes that start up prior to auditd , so that potential malicious activity cannot go undetected.
  "
  impact 1.0
  describe file("/boot/grub2/grubenv") do
    its("content") { should match(/^\s*kernelopts=(\S+\s+)*audit=1\b\s*(\S+\s*)*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.1.4_Ensure_audit_backlog_limit_is_sufficient" do
  title "Ensure audit_backlog_limit is sufficient"
  desc  "
    The backlog limit has a default setting of 64
    
    Rationale: during boot if audit=1, then the backlog will hold 64 records.  If more that 64 records are created during boot, auditd records will be lost and potential malicious activity could go undetected.
  "
  impact 1.0
  describe file("/boot/grub2/grubenv") do
    its("content") { should match(/^\s*kernelopts=(\S+\s+)*audit_backlog_limit=\S+\b\s*(\S+\s*)*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.2.1_Ensure_audit_log_storage_size_is_configured" do
  title "Ensure audit log storage size is configured"
  desc  "
    Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be rotated and a new log file will be started.
    
    Rationale: It is important that an appropriate size is determined for log files so that they do not impact the system and audit data is not lost.
  "
  impact 1.0
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*max_log_file\s*=\s*\S+\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.2.2_Ensure_audit_logs_are_not_automatically_deleted" do
  title "Ensure audit logs are not automatically deleted"
  desc  "
    The max_log_file_action setting determines how to handle the audit log file reaching the max file size. A value of keep_logs will rotate the logs but never delete old logs.
    
    Rationale: In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing the audit history.
  "
  impact 1.0
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*max_log_file_action\s*=\s*keep_logs\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.2.3_Ensure_system_is_disabled_when_audit_logs_are_full" do
  title "Ensure system is disabled when audit logs are full"
  desc  "
    The auditd daemon can be configured to halt the system when the audit logs are full.
    
    Rationale: In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds the benefit of the system's availability.
  "
  impact 1.0
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*space_left_action\s*=\s*email\s*(\s+#.*)?$/) }
  end
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*action_mail_acct\s*=\s*root\s*(\s+#.*)?$/) }
  end
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*admin_space_left_action\s*=\s*halt\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.3_Ensure_changes_to_system_administration_scope_sudoers_is_collected" do
  title "Ensure changes to system administration scope (sudoers) is collected"
  desc  "
    Monitor scope changes for system administrators. If the system has been properly configured to force system administrators to log in as themselves first and then use the sudo command to execute privileged commands, it is possible to monitor changes in scope. The file /etc/sudoers will be written to when the file or its attributes have changed. The audit records will be tagged with the identifier \"scope.\"
    
    Rationale: Changes in the /etc/sudoers file can indicate that an unauthorized change has been made to scope of system administrator activity.
  "
  impact 1.0
  describe auditd do
    its('lines') { should include(%r{-w /etc/sudoers.d[/]? -p wa -k scope}) }
    its('lines') { should include(%r{-w /etc/sudoers -p wa -k scope}) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-w /etc/sudoers -p wa -k scope}) }
    its('content') { should match(%r{-w /etc/sudoers.d[/]? -p wa -k scope}) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.4_Ensure_login_and_logout_events_are_collected" do
  title "Ensure login and logout events are collected"
  desc  "
    Monitor login and logout events. The parameters below track changes to files associated with login/logout events. The file /var/log/faillog tracks failed events from login. The file /var/log/lastlog maintain records of the last time a user successfully logged in.
    
    Rationale: Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins.
  "
  impact 1.0
  describe auditd do
    its('lines') { should include %r(-w /var/log/faillog -p wa -k logins) }
    its('lines') { should include %r(-w /var/log/lastlog -p wa -k logins) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-w /var/log/faillog -p wa -k logins}) }
    its('content') { should match(%r{-w /var/log/lastlog -p wa -k logins}) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.5_Ensure_session_initiation_information_is_collected" do
  title "Ensure session initiation information is collected"
  desc  "
    Monitor session initiation events. The parameters in this section track changes to the files associated with session events. The file /var/run/utmp tracks all currently logged in users. All audit records will be tagged with the identifier \"session.\"  The /var/log/wtmp file tracks logins, logouts, shutdown, and reboot events.  The file /var/log/btmp keeps track of failed login attempts and can be read by entering the command /usr/bin/last -f /var/log/btmp . All audit records will be tagged with the identifier \"logins.\"
    
    Rationale: Monitoring these files for changes could alert a system administrator to logins occurring at unusual hours, which could indicate intruder activity (i.e. a user logging in at a time when they do not normally log in).
  "
  impact 1.0
  describe auditd do
    its('lines') { should include %r(-w /var/run/utmp -p wa -k session) }
    its('lines') { should include %r(-w /var/log/wtmp -p wa -k logins) }
    its('lines') { should include %r(-w /var/log/btmp -p wa -k logins) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-w /var/run/utmp -p wa -k session}) }
    its('content') { should match(%r{-w /var/log/wtmp -p wa -k logins}) }
    its('content') { should match(%r{-w /var/log/btmp -p wa -k logins}) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.6_Ensure_events_that_modify_date_and_time_information_are_collected" do
  title "Ensure events that modify date and time information are collected"
  desc  "
    Capture events where the system date and/or time has been modified. The parameters in this section are set to determine if the adjtimex (tune kernel clock), settimeofday (Set time, using timeval and timezone structures) stime (using seconds since 1/1/1970) or clock_settime (allows for the setting of several internal clocks and timers) system calls have been executed and always write an audit record to the /var/log/audit.log file upon exit, tagging the records with the identifier \"time-change\"
    
    Rationale: Unexpected changes in system date and/or time could be a sign of malicious activity on the system.
  "
  impact 1.0
  describe auditd do
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S clock_settime -F key=time-change}) }
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change}) }
    its('lines') { should include(%r{-w /etc/localtime -p wa -k time-change}) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change}) }
    its('content') { should match(%r{-a always,exit -F arch=b32 -S clock_settime -k time-change}) }
    its('content') { should match(%r{-w /etc/localtime -p wa -k time-change}) }
  end
  if command('uname -m').stdout.strip == 'x86_64'
    describe auditd do
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S clock_settime -F key=time-change}) }
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change}) }
    end
    describe file("/etc/audit/audit.rules") do
      its('content') { should match(%r{-a always,exit -F arch=b64 -S clock_settime -k time-change}) }
      its('content') { should match(%r{-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change}) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.7_Ensure_events_that_modify_the_systems_Mandatory_Access_Controls_are_collected" do
  title "Ensure events that modify the system's Mandatory Access Controls are collected"
  desc  "
    Monitor SELinux/AppArmor mandatory access controls. The parameters below monitor any write access (potential additional, deletion or modification of files in the directory) or attribute changes to the /etc/selinux or /etc/apparmor and /etc/apparmor.d directories.
    
    Rationale: Changes to files in these directories could indicate that an unauthorized user is attempting to modify access controls and change security contexts, leading to a compromise of the system.
  "
  impact 1.0
  if package('apparmor').installed?
    describe auditd do
      its('lines') { should include %r(-w /etc/apparmor[/]? -p wa -k MAC-policy) }
      its('lines') { should include %r(-w /etc/apparmor.d[/]? -p wa -k MAC-policy) }
    end
    describe file("/etc/audit/audit.rules") do
      its('content') { should match(%r{-w /etc/apparmor[/]? -p wa -k MAC-policy}) }
      its('content') { should match(%r{-w /etc/apparmor.d[/]? -p wa -k MAC-policy}) }
    end
  else
    describe auditd do
      its('lines') { should include %r(-w /etc/selinux[/]? -p wa -k MAC-policy) }
      its('lines') { should include %r(-w /usr/share/selinux[/]? -p wa -k MAC-policy) }
    end
    describe file("/etc/audit/audit.rules") do
      its('content') { should match(%r{-w /etc/selinux[/]? -p wa -k MAC-policy}) }
      its('content') { should match(%r{-w /usr/share/selinux[/]? -p wa -k MAC-policy}) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.8_Ensure_events_that_modify_the_systems_network_environment_are_collected" do
  title "Ensure events that modify the system's network environment are collected"
  desc  "
    Record changes to network environment files or system calls. The below parameters monitor the sethostname (set the systems host name) or setdomainname (set the systems domainname) system calls, and write an audit event on system call exit. The other parameters monitor the /etc/issue and /etc/issue.net files (messages displayed pre-login), /etc/hosts (file containing host names and associated IP addresses) and /etc/sysconfig/network (directory containing network interface scripts and configurations) files.
    
    Rationale: Monitoring sethostname and setdomainname will identify potential unauthorized changes to host and domainname of a system. The changing of these names could potentially break security parameters that are set based on those names. The /etc/hosts file is monitored for changes in the file that can indicate an unauthorized intruder is trying to change machine associations with IP addresses and trick users and processes into connecting to unintended machines. Monitoring /etc/issue and /etc/issue.net is important, as intruders could put disinformation into those files and trick users into providing information to the intruder. Monitoring /etc/sysconfig/network is important as it can show if network interfaces or scripts are being modified in a way that can lead to the machine becoming unavailable or compromised. All audit records will be tagged with the identifier \"system-locale.\"
  "
  impact 1.0
  describe auditd do
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale}) }
    its('lines') { should include(%r{-w /etc/issue -p wa -k system-locale}) }
    its('lines') { should include(%r{-w /etc/issue.net -p wa -k system-locale}) }
    its('lines') { should include(%r{-w /etc/hosts -p wa -k system-locale}) }
    its('lines') { should include(%r{-w /etc/sysconfig/network -p wa -k system-locale}) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale}) }
    its('content') { should match(%r{-w /etc/issue -p wa -k system-locale}) }
    its('content') { should match(%r{-w /etc/issue.net -p wa -k system-locale}) }
    its('content') { should match(%r{-w /etc/hosts -p wa -k system-locale}) }
    its('content') { should match(%r{-w /etc/sysconfig/network -p wa -k system-locale}) }
  end
  if command('uname -m').stdout.strip == 'x86_64'
    describe auditd do
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale}) }
    end
    describe file("/etc/audit/audit.rules") do
      its('content') { should match(%r{-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale}) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.9_Ensure_discretionary_access_control_permission_modification_events_are_collected" do
  title "Ensure discretionary access control permission modification events are collected"
  desc  "
    Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls that affect file permissions and attributes. The chmod , fchmod and fchmodat system calls affect the permissions associated with a file. The chown , fchown , fchownat and lchown system calls affect owner and group attributes on a file. The setxattr , lsetxattr , fsetxattr (set extended file attributes) and removexattr , lremovexattr , fremovexattr (remove extended file attributes) control extended file attributes. In all cases, an audit record will only be written for non-system user ids (auid &gt;= 1000) and will ignore Daemon events (auid = 4294967295). All audit records will be tagged with the identifier \"perm_mod.\"
    
    **Note:** Systems may have been customized to change the default UID_MIN.  To confirm the UID_MIN for your system, run the following command:
    
    awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs If your systems' UID_MIN is not 1000 , replace audit&gt;=1000 with audit&gt;=
    <UID_MIN/>
    your system&gt; in the Audit and Remediation procedures.
    
    Rationale: Monitoring for changes in file attributes could alert a system administrator to activity that could indicate intruder activity or policy violation.
  "
  impact 1.0
  describe auditd do
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod}) }
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod}) }
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod}) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod}) }
    its('content') { should match(%r{-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod}) }
    its('content') { should match(%r{-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod}) }
  end
  if command('uname -m').stdout.strip == 'x86_64'
    describe auditd do
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod}) }
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod}) }
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod}) }
    end
    describe file("/etc/audit/audit.rules") do
      its('content') { should match(%r{-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod}) }
      its('content') { should match(%r{-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod}) }
      its('content') { should match(%r{-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod}) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.10_Ensure_unsuccessful_unauthorized_file_access_attempts_are_collected" do
  title "Ensure unsuccessful unauthorized file access attempts are collected"
  desc  "
    Monitor for unsuccessful attempts to access files. The parameters below are associated with system calls that control creation ( creat ), opening ( open , openat ) and truncation ( truncate , ftruncate ) of files. An audit log record will only be written if the user is a non-privileged user (auid &gt; = 1000), is not a Daemon event (auid=4294967295) and if the system call returned EACCES (permission denied to the file) or EPERM (some other permanent error associated with the specific system call). All audit records will be tagged with the identifier \"access.\"
    
    **Note:** Systems may have been customized to change the default UID_MIN.  To confirm the UID_MIN for your system, run the following command:
    
    awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs If your systems' UID_MIN is not 1000 , replace audit&gt;=1000 with audit&gt;=
    <UID_MIN/>
    your system&gt; in the Audit and Remediation procedures.
    
    Rationale: Failed attempts to open, create or truncate files could be an indication that an individual or process is trying to gain unauthorized access to the system.
  "
  impact 1.0
  describe auditd do
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access}) }
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access}) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access}) }
    its('content') { should match(%r{-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access}) }
  end
  if command('uname -m').stdout.strip == 'x86_64'
    describe auditd do
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access}) }
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access}) }
    end
    describe file("/etc/audit/audit.rules") do
      its('content') { should match(%r{-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access}) }
      its('content') { should match(%r{-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access}) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.11_Ensure_events_that_modify_usergroup_information_are_collected" do
  title "Ensure events that modify user/group information are collected"
  desc  "
    Record events affecting the group , passwd (user IDs), shadow and gshadow (passwords) or /etc/security/opasswd (old passwords, based on remember parameter in the PAM configuration) files. The parameters in this section will watch the files to see if they have been opened for write or have had attribute changes (e.g. permissions) and tag them with the identifier \"identity\" in the audit log file.
    
    Rationale: Unexpected changes to these files could be an indication that the system has been compromised and that an unauthorized user is attempting to hide their activities or compromise additional accounts.
  "
  impact 1.0
  describe auditd do
    its('lines') { should include %r(-w /etc/group -p wa -k identity) }
    its('lines') { should include %r(-w /etc/passwd -p wa -k identity) }
    its('lines') { should include %r(-w /etc/gshadow -p wa -k identity) }
    its('lines') { should include %r(-w /etc/shadow -p wa -k identity) }
    its('lines') { should include %r(-w /etc/security/opasswd -p wa -k identity) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-w /etc/group -p wa -k identity}) }
    its('content') { should match(%r{-w /etc/passwd -p wa -k identity}) }
    its('content') { should match(%r{-w /etc/gshadow -p wa -k identity}) }
    its('content') { should match(%r{-w /etc/shadow -p wa -k identity}) }
    its('content') { should match(%r{-w /etc/security/opasswd -p wa -k identity}) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.12_Ensure_successful_file_system_mounts_are_collected" do
  title "Ensure successful file system mounts are collected"
  desc  "
    Monitor the use of the mount system call. The mount (and umount ) system call controls the mounting and unmounting of file systems. The parameters below configure the system to create an audit record when the mount system call is used by a non-privileged user
    
    Rationale: It is highly unusual for a non privileged user to mount file systems to the system. While tracking mount commands gives the system administrator evidence that external media may have been mounted (based on a review of the source of the mount and confirming it's an external media type), it does not conclusively indicate that data was exported to the media. System administrators who wish to determine if data were exported, would also have to track successful open , creat and truncate system calls requiring write access to a file under the mount point of the external media file system. This could give a fair indication that a write occurred. The only way to truly prove it, would be to track successful writes to the external media. Tracking write system calls could quickly fill up the audit log and is not recommended. Recommendations on configuration options to track data export to media is beyond the scope of this document.
    
    **Note:** Systems may have been customized to change the default UID_MIN.  To confirm the UID_MIN for your system, run the following command:
    
    awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs If your systems' UID_MIN is not 1000 , replace audit&gt;=1000 with audit&gt;=
    <UID_MIN/>
    your system&gt; in the Audit and Remediation procedures.
  "
  impact 1.0
  describe auditd do
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts}) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts}) }
  end
  if command('uname -m').stdout.strip == 'x86_64'
    describe auditd do
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts}) }
    end
    describe file("/etc/audit/audit.rules") do
      its('content') { should match(%r{-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts}) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.13_Ensure_use_of_privileged_commands_is_collected" do
  title "Ensure use of privileged commands is collected"
  desc  "
    Monitor privileged programs (those that have the setuid and/or setgid bit set on execution) to determine if unprivileged users are running these commands.
    
    Rationale: Execution of privileged commands by non-privileged users could be an indication of someone trying to gain unauthorized access to the system.
  "
  impact 1.0
  command('find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f').stdout.split("\n").each do |privileged_command|
    describe auditd do
      its('lines') { should include %r(-a always,exit -S all -F path=#{privileged_command} -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.14_Ensure_file_deletion_events_by_users_are_collected" do
  title "Ensure file deletion events by users are collected"
  desc  "
    Monitor the use of system calls associated with the deletion or renaming of files and file attributes. This configuration statement sets up monitoring for the unlink (remove a file), unlinkat (remove a file attribute), rename (rename a file) and renameat (rename a file attribute) system calls and tags them with the identifier \"delete\".
    
    **Note:** Systems may have been customized to change the default UID_MIN.  To confirm the UID_MIN for your system, run the following command:
    
    awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs If your systems' UID_MIN is not 1000 , replace audit&gt;=1000 with audit&gt;=
    <UID_MIN/>
    your system&gt; in the Audit and Remediation procedures.
    
    Rationale: Monitoring these calls from non-privileged users could provide a system administrator with evidence that inappropriate removal of files and file attributes associated with protected files is occurring. While this audit option will look at all events, system administrators will want to look for specific privileged files that are being deleted or altered.
  "
  impact 1.0
  describe auditd do
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete}) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete}) }
  end
  if command('uname -m').stdout.strip == 'x86_64'
    describe auditd do
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete}) }
    end
    describe file("/etc/audit/audit.rules") do
      its('content') { should match(%r{-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete}) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.15_Ensure_kernel_module_loading_and_unloading_is_collected" do
  title "Ensure kernel module loading and unloading is collected"
  desc  "
    Monitor the loading and unloading of kernel modules. The programs insmod (install a kernel module), rmmod (remove a kernel module), and modprobe (a more sophisticated program to load and unload modules, as well as some other features) control loading and unloading of modules. The init_module (load a module) and delete_module (delete a module) system calls control loading and unloading of modules. Any execution of the loading and unloading module programs and system calls will trigger an audit record with an identifier of \"modules\".
    
    Rationale: Monitoring the use of insmod , rmmod and modprobe could provide system administrators with evidence that an unauthorized user loaded or unloaded a kernel module, possibly compromising the security of the system. Monitoring of the init_module and delete_module system calls would reflect an unauthorized user attempting to use a different program to load and unload modules.
  "
  impact 1.0
  describe auditd do
    its('lines') { should include(%r{-w /sbin/insmod -p x -k modules}) }
    its('lines') { should include(%r{-w /sbin/rmmod -p x -k modules}) }
    its('lines') { should include(%r{-w /sbin/modprobe -p x -k modules}) }
    its('lines') { should include(%r{-a always,exit -F arch=b32 -S init_module,delete_module -F key=modules}) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-w /sbin/insmod -p x -k modules}) }
    its('content') { should match(%r{-w /sbin/rmmod -p x -k modules}) }
    its('content') { should match(%r{-w /sbin/modprobe -p x -k modules}) }
    its('content') { should match(%r{-a always,exit -F arch=b32 -S init_module -S delete_module -k modules}) }
  end
  if command('uname -m').stdout.strip == 'x86_64'
    describe auditd do
      its('lines') { should include(%r{-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules}) }
    end
    describe file("/etc/audit/audit.rules") do
      its('content') { should match(%r{-a always,exit -F arch=b64 -S init_module -S delete_module -k modules}) }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.16_Ensure_system_administrator_actions_sudolog_are_collected" do
  title "Ensure system administrator actions (sudolog) are collected"
  desc  "
    Monitor the sudo log file. If the system has been properly configured to disable the use of the su command and force all administrators to have to log in first and then use sudo to execute privileged commands, then all administrator commands will be logged to /var/log/sudo.log . Any time a command is executed, an audit event will be triggered as the /var/log/sudo.log file will be opened for write and the executed administration command will be written to the log.
    
    Rationale: Changes in /var/log/sudo.log indicate that an administrator has executed a command or the log file itself has been tampered with. Administrators will want to correlate the events written to the audit trail with the records written to /var/log/sudo.log to verify if unauthorized commands have been executed.
  "
  impact 1.0
  describe auditd do
    its('lines') { should include(%r{-w /var/log/sudo.log -p wa -k actions}) }
  end
  describe file("/etc/audit/audit.rules") do
    its('content') { should match(%r{-w /var/log/sudo.log -p wa -k actions}) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.1.17_Ensure_the_audit_configuration_is_immutable" do
  title "Ensure the audit configuration is immutable"
  desc  "
    Set system audit so that audit rules cannot be modified with auditctl . Setting the flag \"-e 2\" forces audit to be put in immutable mode. Audit changes can only be made on system reboot.
    
    Rationale: In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. Users would most likely notice a system reboot and that could alert administrators of an attempt to make unauthorized audit changes.
  "
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-e\s+2 *$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.1_Ensure_rsyslog_is_installed" do
  title "Ensure rsyslog is installed"
  desc  "
    The rsyslog software is a recommended replacement to the original syslogd daemon which provide improvements over syslogd , such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server.
    
    Rationale: The security enhancements of rsyslog such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server) justify installing and configuring the package.
  "
  impact 1.0
  describe package("rsyslog") do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.2_Ensure_rsyslog_Service_is_enabled" do
  title "Ensure rsyslog Service is enabled"
  desc  "
    Once the rsyslog package is installed it needs to be activated.
    
    Rationale: If the rsyslog service is not activated the system may default to the syslogd service or lack logging instead.
  "
  impact 1.0
  describe.one do
    describe service('rsyslog') do
      it { should be_running }
      it { should be_enabled }
    end
    describe package('rsyslog') do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.3_Ensure_rsyslog_default_file_permissions_configured" do
  title "Ensure rsyslog default file permissions configured"
  desc  "
    rsyslog will create logfiles that do not already exist on the system. This setting controls what permissions will be applied to these newly created files.
    
    Rationale: It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected.
  "
  impact 1.0
  if package('rsyslog').installed?
    describe.one do
      describe file("/etc/rsyslog.conf") do
        its("content") { should match(/^\s*\$FileCreateMode\s+0[6420][40]0\s*(\s+#.*)?$/) }
      end
      command("find /etc/rsyslog.d/ -type f -regex .\\*/.\\*\\\\.conf").stdout.split.each do |entry|
        describe file(entry) do
          its("content") { should match(/^\s*\$FileCreateMode\s+0[6420][40]0\s*(\s+#.*)?$/) }
        end
      end
    end
  else
    describe package('rsyslog') do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.4_Ensure_logging_is_configured" do
  title "Ensure logging is configured"
  desc  "
    The /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files specifies rules for logging and which files are to be used to log certain classes of messages.
    
    Rationale: A great deal of important security-related information is sent via rsyslog (e.g., successful and failed su attempts, failed login attempts, root login attempts, etc.).
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.5_Ensure_rsyslog_is_configured_to_send_logs_to_a_remote_log_host" do
  title "Ensure rsyslog is configured to send logs to a remote log host"
  desc  "
    The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) or to receive messages from remote hosts, reducing administrative overhead.
    
    Rationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system
  "
  impact 1.0
  if package('rsyslog').installed?
    describe.one do
      describe file("/etc/rsyslog.conf") do
        its("content") { should match(/^\s*\*\.\*\s+@/) }
      end
      command("find /etc/rsyslog.d/ -type f -regex .\\*/.\\*\\\\.conf").stdout.split.each do |entry|
        describe file(entry) do
          its("content") { should match(/^\s*\*\.\*\s+@/) }
        end
      end
    end
  else
    describe package('rsyslog') do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.6_Ensure_remote_rsyslog_messages_are_only_accepted_on_designated_log_hosts." do
  title "Ensure remote rsyslog messages are only accepted on designated log hosts."
  desc  "
    By default, rsyslog does not listen for log messages coming in from remote systems. The ModLoad tells rsyslog to load the imtcp.so module so it can listen over a network via TCP. The InputTCPServerRun option instructs rsyslogd to listen on the specified TCP port.
    
    Rationale: The guidance in the section ensures that remote log hosts are configured to only accept rsyslog data from hosts within the specified domain and that those systems that are not designed to be log hosts do not accept any remote rsyslog messages. This provides protection from spoofed log data and ensures that system administrators are reviewing reasonably complete syslog data in a central location.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.2.1_Ensure_journald_is_configured_to_send_logs_to_rsyslog" do
  title "Ensure journald is configured to send logs to rsyslog"
  desc  "
    Data from journald may be stored in volatile memory or persisted locally on the server.  Utilities exist to accept remote export of journald logs, however, use of the rsyslog service provides a consistent means of log collection and export.
    
    Rationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.
  "
  impact 1.0
  describe file("/etc/systemd/journald.conf") do
    its("content") { should match(/^\s*(?i)ForwardToSyslog\s*=\s*yes(\s+#.*)*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.2.2_Ensure_journald_is_configured_to_compress_large_log_files" do
  title "Ensure journald is configured to compress large log files"
  desc  "
    The journald system includes the capability of compressing overly large files to avoid filling up the system with logs or making the logs unmanageably large.
    
    Rationale: Uncompressed large files may unexpectedly fill a filesystem leading to resource unavailability.  Compressing logs prior to write can prevent sudden, unexpected filesystem impacts.
  "
  impact 1.0
  describe file("/etc/systemd/journald.conf") do
    its("content") { should match(/^\s*(?i)Compress\s*=\s*yes(\s+#.*)*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.2.3_Ensure_journald_is_configured_to_write_logfiles_to_persistent_disk" do
  title "Ensure journald is configured to write logfiles to persistent disk"
  desc  "
    Data from journald may be stored in volatile memory or persisted locally on the server.  Logs in memory will be lost upon a system reboot.  By persisting logs to local disk on the server they are protected from loss.
    
    Rationale: Writing log data to disk will provide the ability to forensically reconstruct events which may have impacted the operations or security of a system even after a system crash or reboot.
  "
  impact 1.0
  describe file("/etc/systemd/journald.conf") do
    its("content") { should match(/^\s*(?i)Storage\s*=\s*persistent(\s+#.*)*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.3_Ensure_permissions_on_all_logfiles_are_configured" do
  title "Ensure permissions on all logfiles are configured"
  desc  "
    Log files stored in /var/log/ contain logged information from many services on the system, or on log hosts others as well.
    
    Rationale: It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected.
  "
  impact 1.0
  command('find /var/log -type f -perm /037 -o -type d -perm /026').stdout.split("\n").each do |log_file|
    describe file(log_file) do
      it { should_not be_writable.by('group') }
      it { should_not be_executable.by('group') }
      it { should_not be_readable.by('other') }
      it { should_not be_writable.by('other') }
      it { should_not be_executable.by('other') }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.3_Ensure_logrotate_is_configured" do
  title "Ensure logrotate is configured"
  desc  "
    The system includes the capability of rotating log files regularly to avoid filling up the system with logs or making the logs unmanageably large. The file /etc/logrotate.d/syslog is the configuration file used to rotate log files created by syslog or rsyslog .
    
    Rationale: By keeping the log files smaller and more manageable, a system administrator can easily archive these files to another system and spend less time looking through inordinately large log files.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.1_Ensure_cron_daemon_is_enabled" do
  title "Ensure cron daemon is enabled"
  desc  "
    The cron daemon is used to execute batch jobs on the system.
    
    Rationale: While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include security monitoring that have to run, and cron is used to execute them.
  "
  impact 1.0
  describe service('crond') do
    it { should be_enabled }
    it { should be_running }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.2_Ensure_permissions_on_etccrontab_are_configured" do
  title "Ensure permissions on /etc/crontab are configured"
  desc  "
    The /etc/crontab file is used by cron to control its own jobs. The commands in this item make sure that root is the user and group owner of the file and that only the owner can access the file.
    
    Rationale: This file contains information on what system jobs are run by cron. Write access to these files could provide unprivileged users with the ability to elevate their privileges. Read access to these files could provide users with the ability to gain insight on system jobs that run on the system and could provide them a way to gain unauthorized privileged access.
  "
  impact 1.0
  describe file("/etc/crontab") do
    it { should exist }
  end
  describe file("/etc/crontab") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/crontab") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/crontab") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/crontab") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.3_Ensure_permissions_on_etccron.hourly_are_configured" do
  title "Ensure permissions on /etc/cron.hourly are configured"
  desc  "
    This directory contains system cron jobs that need to run on an hourly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  describe file("/etc/cron.hourly") do
    it { should exist }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.4_Ensure_permissions_on_etccron.daily_are_configured" do
  title "Ensure permissions on /etc/cron.daily are configured"
  desc  "
    The /etc/cron.daily directory contains system cron jobs that need to run on a daily basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  describe file("/etc/cron.daily") do
    it { should exist }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.daily") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.daily") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.5_Ensure_permissions_on_etccron.weekly_are_configured" do
  title "Ensure permissions on /etc/cron.weekly are configured"
  desc  "
    The /etc/cron.weekly directory contains system cron jobs that need to run on a weekly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  describe file("/etc/cron.weekly") do
    it { should exist }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.6_Ensure_permissions_on_etccron.monthly_are_configured" do
  title "Ensure permissions on /etc/cron.monthly are configured"
  desc  "
    The /etc/cron.monthly directory contains system cron jobs that need to run on a monthly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  describe file("/etc/cron.monthly") do
    it { should exist }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.7_Ensure_permissions_on_etccron.d_are_configured" do
  title "Ensure permissions on /etc/cron.d are configured"
  desc  "
    The /etc/cron.d directory contains system cron jobs that need to run in a similar manner to the hourly, daily weekly and monthly jobs from /etc/crontab , but require more granular control as to when they run. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.
    
    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  describe file("/etc/cron.d") do
    it { should exist }
  end
  describe file("/etc/cron.d") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.d") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.d") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.d") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.1.8_Ensure_atcron_is_restricted_to_authorized_users" do
  title "Ensure at/cron is restricted to authorized users"
  desc  "
    Configure /etc/cron.allow and /etc/at.allow to allow specific users to use these services. If /etc/cron.allow or /etc/at.allow do not exist, then /etc/at.deny and /etc/cron.deny are checked. Any user not specifically defined in those files is allowed to use at and cron. By removing the files, only users in /etc/cron.allow and /etc/at.allow are allowed to use at and cron. Note that even though a given user is not listed in cron.allow , cron jobs can still be run as that user. The cron.allow file only controls administrative access to the crontab command for scheduling and modifying cron jobs.
    
    Rationale: On many systems, only the system administrator is authorized to schedule cron jobs. Using the cron.allow file to control who can run cron jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files.
  "
  impact 1.0
  describe file("/etc/at.allow") do
    it { should exist }
  end
  describe file("/etc/at.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/at.allow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/at.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/at.allow") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/cron.deny") do
    it { should_not exist }
  end
  describe file("/etc/at.deny") do
    it { should_not exist }
  end
  describe file("/etc/cron.allow") do
    it { should exist }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.allow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.allow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.1_Ensure_permissions_on_etcsshsshd_config_are_configured" do
  title "Ensure permissions on /etc/ssh/sshd_config are configured"
  desc  "
    The /etc/ssh/sshd_config file contains configuration specifications for sshd . The command below sets the owner and group of the file to root.
    
    Rationale: The /etc/ssh/sshd_config file needs to be protected from unauthorized changes by non-privileged users.
  "
  impact 1.0
  describe file('/etc/ssh/sshd_config') do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('group') }
    it { should_not be_executable.by('other') }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.2_Ensure_SSH_access_is_limited" do
  title "Ensure SSH access is limited"
  desc  "
    There are several options available to limit which users and group can access the system via SSH. It is recommended that at least one of the following options be leveraged:
    
    AllowUsers
    
    The AllowUsers variable gives the system administrator the option of allowing specific users to ssh into the system. The list consists of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by only allowing the allowed users to log in from a particular host, the entry can be specified in the form of user@host.
    
    AllowGroups
    
    The AllowGroups variable gives the system administrator the option of allowing specific groups of users to ssh into the system. The list consists of space separated group names. Numeric group IDs are not recognized with this variable.
    
    DenyUsers
    
    The DenyUsers variable gives the system administrator the option of denying specific users to ssh into the system. The list consists of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by specifically denying a user's access from a particular host, the entry can be specified in the form of user@host.
    
    DenyGroups
    
    The DenyGroups variable gives the system administrator the option of denying specific groups of users to ssh into the system. The list consists of space separated group names. Numeric group IDs are not recognized with this variable.
    
    Rationale: Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system.
  "
  impact 1.0
  describe.one do
    describe file('/etc/ssh/sshd_config') do
      its('content') { should match(/^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\s+(\S+)/) }
    end
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.3_Ensure_permissions_on_SSH_private_host_key_files_are_configured" do
  title "Ensure permissions on SSH private host key files are configured"
  desc  "
    An SSH private key is one of two files used in SSH public key authentication.  In this authentication method, the possession of the private key is proof of identity. Only a private key that corresponds to a public key will be able to authenticate successfully. The private keys need to be stored and handled carefully, and no copies of the private key should be distributed.
    
    Rationale: If an unauthorized user obtains the private SSH host key file, the host could be impersonated
  "
  impact 1.0
  command("find /etc/ssh/ -type f -name ssh_host_*_key").stdout.split.each do |entry|
    describe file(entry) do
      it { should exist }
      it { should_not be_executable.by "group" }
      it { should_not be_readable.by "group" }
      its("gid") { should cmp 0 }
      it { should_not be_writable.by "group" }
      it { should_not be_executable.by "other" }
      it { should_not be_readable.by "other" }
      it { should_not be_writable.by "other" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.4_Ensure_permissions_on_SSH_public_host_key_files_are_configured" do
  title "Ensure permissions on SSH public host key files are configured"
  desc  "
    An SSH public key is one of two files used in SSH public key authentication. In this authentication method, a public key is a key that can be used for verifying digital signatures generated using a corresponding private key. Only a public key that corresponds to a private key will be able to authenticate successfully.
    
    Rationale: If a public host key file is modified by an unauthorized user, the SSH service may be compromised.
  "
  impact 1.0
  command("find /etc/ssh/ -type f -name ssh_host_*_key.pub").stdout.split.each do |entry|
    describe file(entry) do
      it { should exist }
      it { should_not be_executable.by "group" }
      its("gid") { should cmp 0 }
      it { should_not be_writable.by "group" }
      it { should_not be_executable.by "other" }
      it { should_not be_writable.by "other" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.5_Ensure_SSH_LogLevel_is_appropriate" do
  title "Ensure SSH LogLevel is appropriate"
  desc  "
    INFO level is the basic level that only records login activity of SSH users. In many situations, such as Incident Response, it is important to determine when a particular user was active on a system. The logout record can eliminate those users who disconnected, which helps narrow the field.
    
    VERBOSE level specifies that login and logout activity as well as the key fingerprint for any SSH key used for login will be logged. This information is important for SSH key management, especially in legacy environments.
    
    Rationale: SSH provides several logging levels with varying amounts of verbosity. DEBUG is specifically **not** recommended other than strictly for debugging SSH communications since it provides so much data that it is difficult to identify important security information.
  "
  impact 1.0
  describe sshd_config do
    its('LogLevel') { should match(/^(VERBOSE|INFO)$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.6_Ensure_SSH_X11_forwarding_is_disabled" do
  title "Ensure SSH X11 forwarding is disabled"
  desc  "
    The X11Forwarding parameter provides the ability to tunnel X11 traffic through the connection to enable remote graphic connections.
    
    Rationale: Disable X11 forwarding unless there is an operational requirement to use X11 applications directly. There is a small risk that the remote X11 servers of users who are logged in via SSH with X11 forwarding could be compromised by other users on the X11 server. Note that even if X11 forwarding is disabled, users can always install their own forwarders.
  "
  impact 1.0
  describe sshd_config do
    its('X11Forwarding') { should eq 'no' }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.7_Ensure_SSH_MaxAuthTries_is_set_to_4_or_less" do
  title "Ensure SSH MaxAuthTries is set to 4 or less"
  desc  "
    The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection. When the login failure count reaches half the number, error messages will be written to the syslog file detailing the login failure.
    
    Rationale: Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. While the recommended setting is 4, set the number based on site policy.
  "
  impact 1.0
  describe sshd_config do
    its('MaxAuthTries') { should cmp <= 4 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.8_Ensure_SSH_IgnoreRhosts_is_enabled" do
  title "Ensure SSH IgnoreRhosts is enabled"
  desc  "
    The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication .
    
    Rationale: Setting this parameter forces users to enter a password when authenticating with ssh.
  "
  impact 1.0
  describe sshd_config do
    its('IgnoreRhosts') { should eq 'yes' }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.9_Ensure_SSH_HostbasedAuthentication_is_disabled" do
  title "Ensure SSH HostbasedAuthentication is disabled"
  desc  "
    The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user of .rhosts , or /etc/hosts.equiv , along with successful public key client host authentication. This option only applies to SSH Protocol Version 2.
    
    Rationale: Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf , disabling the ability to use .rhosts files in SSH provides an additional layer of protection.
  "
  impact 1.0
  describe sshd_config do
    its('HostbasedAuthentication') { should eq 'no' }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.10_Ensure_SSH_root_login_is_disabled" do
  title "Ensure SSH root login is disabled"
  desc  "
    The PermitRootLogin parameter specifies if the root user can log in using ssh. The default is no.
    
    Rationale: Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalating to root via sudo or su . This in turn limits opportunity for non-repudiation and provides a clear audit trail in the event of a security incident
  "
  impact 1.0
  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.11_Ensure_SSH_PermitEmptyPasswords_is_disabled" do
  title "Ensure SSH PermitEmptyPasswords is disabled"
  desc  "
    The PermitEmptyPasswords parameter specifies if the SSH server allows login to accounts with empty password strings.
    
    Rationale: Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system
  "
  impact 1.0
  describe sshd_config do
    its('PermitEmptyPasswords') { should eq 'no' }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.12_Ensure_SSH_PermitUserEnvironment_is_disabled" do
  title "Ensure SSH PermitUserEnvironment is disabled"
  desc  "
    The PermitUserEnvironment option allows users to present environment options to the ssh daemon.
    
    Rationale: Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to bypass security controls (e.g. setting an execution path that has ssh executing trojan'd programs)
  "
  impact 1.0
  describe sshd_config do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.13_Ensure_SSH_Idle_Timeout_Interval_is_configured" do
  title "Ensure SSH Idle Timeout Interval is configured"
  desc  "
    The two options ClientAliveInterval and ClientAliveCountMax control the timeout of ssh sessions. When the ClientAliveInterval variable is set, ssh sessions that have no activity for the specified length of time are terminated. When the ClientAliveCountMax variable is set, sshd will send client alive messages at every ClientAliveInterval interval. When the number of consecutive client alive messages are sent with no response from the client, the ssh session is terminated. For example, if the ClientAliveInterval is set to 15 seconds and the ClientAliveCountMax is set to 3, the client ssh session will be terminated after 45 seconds of idle time.
    
    Rationale: Having no timeout value associated with a connection could allow an unauthorized user access to another user's ssh session (e.g. user walks away from their computer and doesn't lock the screen). Setting a timeout value at least reduces the risk of this happening..
    
    While the recommended setting is 300 seconds (5 minutes), set this timeout value based on site policy. The recommended setting for ClientAliveCountMax is 0. In this case, the client session will be terminated after 5 minutes of idle time and no keepalive messages will be sent.
  "
  impact 1.0
  describe sshd_config do
    its('ClientAliveInterval') { should cmp <=  300 }
    its('ClientAliveInterval') { should cmp > 0 }
    its('ClientAliveCountMax') { should cmp <= 3 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.14_Ensure_SSH_LoginGraceTime_is_set_to_one_minute_or_less" do
  title "Ensure SSH LoginGraceTime is set to one minute or less"
  desc  "
    The LoginGraceTime parameter specifies the time allowed for successful authentication to the SSH server. The longer the Grace period is the more open unauthenticated connections can exist. Like other session controls in this session the Grace Period should be limited to appropriate organizational limits to ensure the service is available for needed access.
    
    Rationale: Setting the LoginGraceTime parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. It will also limit the number of concurrent unauthenticated connections While the recommended setting is 60 seconds (1 Minute), set the number based on site policy.
  "
  impact 1.0
  describe sshd_config do
    its('LoginGraceTime') { should cmp <= 60 }
    its('LoginGraceTime') { should cmp > 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.15_Ensure_SSH_warning_banner_is_configured" do
  title "Ensure SSH warning banner is configured"
  desc  "
    The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted. By default, no banner is displayed.
    
    Rationale: Banners are used to warn connecting users of the particular site's policy regarding connection. Presenting a warning message prior to the normal user login may assist the prosecution of trespassers on the computer system.
  "
  impact 1.0
  describe sshd_config do
    its('Banner') { should_not be_nil }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.16_Ensure_SSH_PAM_is_enabled" do
  title "Ensure SSH PAM is enabled"
  desc  "
    UsePAM Enables the Pluggable Authentication Module interface. If set to &#x201C;yes&#x201D; this will enable PAM authentication using ChallengeResponseAuthentication and PasswordAuthentication in addition to PAM account and session module processing for all authentication types
    
    Rationale: When usePAM is set to yes, PAM runs through account and session types properly.  This is important if you want to restrict access to services based off of IP, time or other factors of the account. Additionally, you can make sure users inherit certain environment variables on login or disallow access to the server
  "
  impact 1.0
  describe sshd_config do
    its('UsePAM') { should eq 'yes' }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.17_Ensure_SSH_AllowTcpForwarding_is_disabled" do
  title "Ensure SSH AllowTcpForwarding is disabled"
  desc  "
    SSH port forwarding is a mechanism in SSH for tunneling application ports from the client to the server, or servers to clients. It can be used for adding encryption to legacy applications, going through firewalls, and some system administrators and IT professionals use it for opening backdoors into the internal network from their home machines
    
    Rationale: Leaving port forwarding enabled can expose the organization to security risks and back-doors.
    
    SSH connections are protected with strong encryption. This makes their contents invisible to most deployed network monitoring and traffic filtering solutions. This invisibility carries considerable risk potential if it is used for malicious purposes such as data exfiltration. Cybercriminals or malware could exploit SSH to hide their unauthorized communications, or to exfiltrate stolen data from the target network
  "
  impact 1.0
  describe sshd_config do
    its('AllowTcpForwarding') { should eq 'no' }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.18_Ensure_SSH_MaxStartups_is_configured" do
  title "Ensure SSH MaxStartups is configured"
  desc  "
    The MaxStartups parameter specifies the  maximum number of concurrent unauthenticated connections to the SSH daemon.
    
    Rationale: To protect a system from denial of service due to a large number of pending authentication connection attempts, use the rate limiting function of MaxStartups to protect availability of sshd logins and prevent overwhelming the daemon.
  "
  impact 1.0
  describe sshd_config do
    its('MaxStartups') { should eq '10:30:60' }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.19_Ensure_SSH_MaxSessions_is_set_to_4_or_less" do
  title "Ensure SSH MaxSessions is set to 4 or less"
  desc  "
    The MaxSessions parameter specifies the maximum number of open sessions permitted from a given connection.
    
    Rationale: To protect a system from denial of service due to a large number of concurrent sessions, use the rate limiting function of MaxSessions to protect availability of sshd logins and prevent overwhelming the daemon.
  "
  impact 1.0
  describe sshd_config do
    its('MaxSessions') { should cmp <= 4 }
    its('MaxSessions') { should cmp > 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.2.20_Ensure_system-wide_crypto_policy_is_not_over-ridden" do
  title "Ensure system-wide crypto policy is not over-ridden"
  desc  "
    System-wide Crypto policy can be over-ridden or opted out of for openSSH
    
    Rationale: Over-riding or opting out of the system-wide crypto policy could allow for the use of less secure Ciphers, MACs, KexAlgoritms and GSSAPIKexAlgorithsm
  "
  impact 1.0
  describe file("/etc/sysconfig/sshd") do
    its("content") { should_not match(/^\s*(CRYPTO_POLICY|[Cc]rypto_[Pp]olicy)\s*=.*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.3.1_Create_custom_authselect_profile" do
  title "Create custom authselect profile"
  desc  "
    A custom profile can be created by copying and customizing one of the default profiles.  The default profiles include: sssd, winbind, or the nis.
    
    Rationale: A custom profile is required to customize many of the pam options
  "
  impact 1.0
  describe command("authselect current | grep 'Profile ID:'") do
    its('stdout') { should match(/^\s*Profile\s+ID:\s+custom\//) }
    its('exit_status') { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.3.2_Select_authselect_profile" do
  title "Select authselect profile"
  desc  "
    You can select a profile for the authselect utility for a specific host. The profile will be applied to every user logging into the host.
    
    You can create and deploy a custom profile by customizing one of the default profiles, the sssd, winbind, or the nis profile.
    
    Rationale: When you deploy a profile, the profile is applied to every user logging into the given host
  "
  impact 1.0
  describe file("/etc/authselect/authselect.conf") do
    its("content") { should match(/^\s*custom\/\S+\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.3.3_Ensure_authselect_includes_with-faillock" do
  title "Ensure authselect includes with-faillock"
  desc  "
    The pam_faillock.so module maintains a list of failed authentication attempts per user during a specified interval and locks the account in case there were more than deny consecutive failed authentications. It stores the failure records into per-user files in the tally directory
    
    Rationale: Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  impact 1.0
  describe file("/etc/authselect/authselect.conf") do
    its("content") { should match(/^\s*with-faillock/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.1_Ensure_password_creation_requirements_are_configured" do
  title "Ensure password creation requirements are configured"
  desc  "
    The pam_pwquality.so module checks the strength of passwords. It performs checks such as making sure a password is not a dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more. The following are definitions of the pam_pwquality.so options.
    
    * try_first_pass - retrieve the password from a previous stacked PAM module. If not available, then prompt the user for a password.
    * retry=3 - Allow 3 tries before sending back a failure.
    * minlen=14 - password must be 14 characters or more
    ** Either of the following can be used to enforce complex passwords:**
    
    * minclass=4 - provide at least four classes of characters for the new password
    **OR**
    
    * dcredit=-1 - provide at least one digit
    * ucredit=-1 - provide at least one uppercase character
    * ocredit=-1 - provide at least one special character
    * lcredit=-1 - provide at least one lowercase character
    The settings shown above are one possible policy. Alter these values to conform to your own organization's password policies
    
    Rationale: Strong passwords protect systems from being hacked through brute force methods.
  "
  impact 1.0
  describe file("/etc/pam.d/password-auth") do
    its("content") { should match(/^\s*password\s+requisite\s+pam_pwquality.so\s+(\S+\s+)*retry=[1-3]\s*(\s+\S+\s*)*(\s+#.*)*$/) }
  end
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+requisite\s+pam_pwquality.so\s+(\S+\s+)*retry=[1-3]\s*(\s+\S+\s*)*(\s+#.*)*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*minlen\s*=\s*(1[4-9]|[2-9][0-9]|[1-9][0-9][0-9])(\s+#.*)*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.2_Ensure_lockout_for_failed_password_attempts_is_configured" do
  title "Ensure lockout for failed password attempts is configured"
  desc  "
    Lock out users after **n** unsuccessful consecutive login attempts.
    
    * deny= - Number of attempts before the account is locked
    
    * unlock_time= - Time in seconds before the account is unlocked
    
    Set the lockout number and unlock time to follow local site policy.
    
    Rationale: Locking out user IDs after **n** unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  impact 1.0
  describe file("/etc/pam.d/password-auth") do
    its("content") { should match(/^\s*auth\s+required\s+.*\s+deny=[1-5]\s*.*$/) }
  end
  describe file("/etc/pam.d/password-auth") do
    its("content") { should match(/^\s*auth\s+required\s+.*\s+unlock_time=(9[0-9][0-9]|[1-9][0-9][0-9][0-9])\s*.*$/) }
  end
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*auth\s+required\s+.*\s+deny=[1-5]\s*.*$/) }
  end
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*auth\s+required\s+.*\s+unlock_time=(9[0-9][0-9]|[1-9][0-9][0-9][0-9])\s*.*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.3_Ensure_password_reuse_is_limited" do
  title "Ensure password reuse is limited"
  desc  "
    The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords.
    
    * remember=5&gt; - Number of old passwords to remember
    
    Rationale: Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to guess the password.
    
    Note that these change only apply to accounts configured on the local system.
  "
  impact 1.0
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(requisite|sufficient)\s+(pam_pwhistory\.so|pam_unix\.so)\s+(\S+\s+)*remember=([5-9]|[1-4][0-9])[0-9]*(\s+\S+\s*)*(\s+#.*)*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.4.4_Ensure_password_hashing_algorithm_is_SHA-512" do
  title "Ensure password hashing algorithm is SHA-512"
  desc  "
    The commands below change password encryption from md5 to sha512 (a much stronger hashing algorithm). All existing accounts will need to perform a password change to upgrade the stored hashes to the new algorithm.
    
    Rationale: The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system by increasing the level of effort for an attacker to successfully determine passwords.
    
    Note that these changes only apply to accounts configured on the local system.
  "
  impact 1.0
  describe file("/etc/pam.d/password-auth") do
    its("content") { should match(/^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512\s*.*$/) }
  end
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512\s*.*$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.5.1.1_Ensure_password_expiration_is_365_days_or_less" do
  title "Ensure password expiration is 365 days or less"
  desc  "
    The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age.  It is recommended that the PASS_MAX_DAYS parameter be set to less than or equal to 365 days.
    
    Rationale: The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity.
  "
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MAX_DAYS\s+(36[0-5]|3[0-5][0-9]|[1-2][0-9][0-9]|[1-9][0-9]?)\s*(\s+#.*)?$/) }
  end
  describe shadow.where { user =~ /.+/ and password =~ /^[^!*]/ and (max_days.nil? or max_days.to_i > 365) } do
    its("raw_data") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.5.1.2_Ensure_minimum_days_between_password_changes_is_7_or_more" do
  title "Ensure minimum days between password changes is 7 or more"
  desc  "
    The PASS_MIN_DAYS parameter in /etc/login.defs allows an administrator to prevent users from changing their password until a minimum number of days have passed since the last time the user changed their password. It is recommended that PASS_MIN_DAYS parameter be set to 7 or more days.
    
    Rationale: By restricting the frequency of password changes, an administrator can prevent users from repeatedly changing their password in an attempt to circumvent password reuse controls.
  "
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MIN_DAYS\s+([789]|[1-9][0-9]+)\s*(\s+#.*)?$/) }
  end
  describe shadow.where { user =~ /.+/ and password =~ /^[^!*]/ and (min_days.nil? or min_days.to_i < 7) } do
    its("raw_data") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.5.1.3_Ensure_password_expiration_warning_days_is_7_or_more" do
  title "Ensure password expiration warning days is 7 or more"
  desc  "
    The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users that their password will expire in a defined number of days. It is recommended that the PASS_WARN_AGE parameter be set to 7 or more days.
    
    Rationale: Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password or write it down where it may be discovered.
  "
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_WARN_AGE\s+([789]|[1-9][0-9]+)\s*(\s+#.*)?$/) }
  end
  describe shadow.where { user =~ /.+/ and password =~ /^[^!*]/ and (warn_days.nil? or warn_days.to_i < 7) } do
    its("raw_data") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.5.1.4_Ensure_inactive_password_lock_is_30_days_or_less" do
  title "Ensure inactive password lock is 30 days or less"
  desc  "
    User accounts that have been inactive for over a given period of time can be automatically disabled. It is recommended that accounts that are inactive for 30 days after password expiration be disabled.
    
    Rationale: Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies.
  "
  impact 1.0
  describe file("/etc/default/useradd") do
    its("content") { should match(/^\s*INACTIVE\s*=\s*(30|[1-2][0-9]|[1-9])\s*(\s+#.*)?$/) }
  end
  describe shadow.where { user =~ /.+/ and password =~ /^[^!*]/ and (inactive_days.nil? or inactive_days.to_i > 30) } do
    its("raw_data") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.5.1.5_Ensure_all_users_last_password_change_date_is_in_the_past" do
  title "Ensure all users last password change date is in the past"
  desc  "
    All users should have a password change date in the past.
    
    Rationale: If a users recorded password change date is in the future then they could bypass any set password expiration.
  "
  impact 1.0
  today = (DateTime.now.to_time.to_i)/86400
  describe shadow.where { user =~ /.+/ and password !~ /^!/ and last_change.to_i >= today } do
    its('entries') { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.5.2_Ensure_system_accounts_are_secured" do
  title "Ensure system accounts are secured"
  desc  "
    There are a number of accounts provided with most distributions that are used to manage applications and are not intended to provide an interactive shell.
    
    Rationale: It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, most distributions set the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to the nologin shell. This prevents the account from potentially being used to run any commands.
  "
  impact 1.0
  describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ } do
    its("entries") { should_not be_empty }
  end
  describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ && uid.to_i < 500 && shell != "/sbin/nologin" } do
    its("entries") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.5.3_Ensure_default_user_shell_timeout_is_900_seconds_or_less" do
  title "Ensure default user shell timeout is 900 seconds or less"
  desc  "
    The default TMOUT determines the shell timeout for users.  The TMOUT value is measured in seconds.
    
    Rationale: Having no timeout value associated with a shell could allow an unauthorized user access to another user's shell session (e.g. user walks away from their computer and doesn't lock the screen).  Setting a timeout value at least reduces the risk of this happening.
  "
  impact 1.0
  describe file("/etc/bashrc") do
    its("content") { should match(/^\s*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\s*(\s+#.*)?$/) }
  end
  describe file("/etc/bashrc") do
    its("content") { should_not match(/^\s*TMOUT=(90[1-9]|9[1-9][0-9]|[1-9][0-9]{3,})\s*(\s+#.*)?$/) }
  end
  describe file("/etc/profile") do
    its("content") { should match(/^\s*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\s*(\s+#.*)?$/) }
  end
  describe file("/etc/profile") do
    its("content") { should_not match(/^\s*TMOUT=(90[1-9]|9[1-9][0-9]|[1-9][0-9]{3,})\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.5.4_Ensure_default_group_for_the_root_account_is_GID_0" do
  title "Ensure default group for the root account is GID 0"
  desc  "
    The usermod command can be used to specify which group the root user belongs to. This affects permissions of files that are created by the root user.
    
    Rationale: Using GID 0 for the root account helps prevent root -owned files from accidentally becoming accessible to non-privileged users.
  "
  impact 1.0
  describe passwd.where { user == "root" } do
    its("entries") { should_not be_empty }
  end
  describe passwd.where { user == "root" && gid.to_i == 0 } do
    its("entries") { should_not be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.5.5_Ensure_default_user_umask_is_027_or_more_restrictive" do
  title "Ensure default user umask is 027 or more restrictive"
  desc  "
    The default umask determines the permissions of files created by users. The user creating the file has the discretion of making their files and directories readable by others via the chmod command. Users who wish to allow their files and directories to be readable by others by default may choose a different default umask by inserting the umask command into the standard shell configuration files ( .profile , .bashrc , etc.) in their home directories.
    
    Rationale: Setting a very secure default value for umask ensures that users make a conscious choice about their file permissions. A default umask setting of 077 causes files and directories created by users to not be readable by any other user on the system. A umask of 027 would make files and directories readable by users in the same Unix group, while a umask of 022 would make files readable by every user on the system.
  "
  impact 1.0
  describe file("/etc/bashrc") do
    its("content") { should match(/^\s*umask\s+[01234567][2367]7\s*(\s+#.*)?$/) }
    its("content") { should_not match(/^\s*umask\s+[01234567](0[7654321]|[7654321][654321])\s*(\s+#.*)?$/) }
  end
  describe.one do
    describe file("/etc/profile") do
      its("content") { should_not match(/^\s*umask\s+[01234567](0[7654321]|[7654321][654321])\s*(\s+#.*)?$/) }
    end
    files = command("find /etc/profile.d/ -type f -regex .\\*/.\\*\\\\.sh").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*umask\s+[01234567][2367]7\s*(\s+#.*)?$/ } do
      it { should_not be_empty }
    end
  end
  describe file("/etc/profile") do
    its("content") { should match(/^\s*umask\s+[01234567][2367]7\s*(\s+#.*)?$/) }
  end
  files = command("find /etc/profile.d/ -type f -regex .\\*/.\\*\\\\.sh").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*umask\s+[01234567](0[7654321]|[7654321][654321])\s*(\s+#.*)?$/ } do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.6_Ensure_root_login_is_restricted_to_system_console" do
  title "Ensure root login is restricted to system console"
  desc  "
    The file /etc/securetty contains a list of valid terminals that may be logged in directly as root.
    
    Rationale: Since the system console has special properties to handle emergency situations, it is important to ensure that the console is in a physically secure location and that unauthorized consoles have not been defined.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_5.7_Ensure_access_to_the_su_command_is_restricted" do
  title "Ensure access to the su command is restricted"
  desc  "
    The su command allows a user to run a command or shell as another user. The program has been superseded by sudo , which allows for more granular control over privileged access. Normally, the su command can be executed by any user. By uncommenting the pam_wheel.so statement in /etc/pam.d/su , the su command will only allow users in the wheel group to execute su .
    
    Rationale: Restricting the use of su , and using sudo in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands. The sudo utility also provides a better logging and audit mechanism, as it can log each command executed via sudo , whereas su can only record that a user executed the su program.
  "
  impact 1.0
  describe file("/etc/pam.d/su") do
    its("content") { should match(/^\s*auth\s+required\s+pam_wheel.so(\s+\S+)*\s+use_uid(\s+\S+)*\s*(\s+#.*)?$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.1_Audit_system_file_permissions" do
  title "Audit system file permissions"
  desc  "
    The RPM package manager has a number of useful options. One of these, the -V for RPM option, can be used to verify that system packages are correctly installed. The -V option can be used to verify a particular package or to verify all system packages. If no output is returned, the package is installed correctly. The following table describes the meaning of output from the verify option:
    
    Code   Meaning
    S      File size differs.
    M      File mode differs (includes permissions and file type).
    5      The MD5 checksum differs.
    D      The major and minor version numbers differ on a device file.
    L      A mismatch occurs in a link.
    U      The file ownership differs.
    G      The file group owner differs.
    T      The file time (mtime) differs. The rpm -qf command can be used to determine which package a particular file belongs to. For example the following commands determines which package the /bin/bash file belongs to:
    
    # rpm -qf /bin/bash
    bash-4.1.2-29.el6.x86_64
    # dpkg -S /bin/bash
    bash: /bin/bash To verify the settings for the package that controls the /bin/bash file, run the following:
    
    # rpm -V bash-4.1.2-29.el6.x86_64
    .M.......    /bin/bash
    # dpkg --verify bash
    ??5?????? c /etc/bash.bashrc Note that you can feed the output of the rpm -qf command to the rpm -V command:
    
    # rpm -V `rpm -qf /etc/passwd`
    .M...... c /etc/passwd
    S.5....T c /etc/printcap
    
    Rationale: It is important to confirm that packaged system files and directories are maintained with the permissions they were intended to have from the OS vendor.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.2_Ensure_permissions_on_etcpasswd_are_configured" do
  title "Ensure permissions on /etc/passwd are configured"
  desc  "
    The /etc/passwd file contains user account information that is used by many system utilities and therefore must be readable for these utilities to operate.
    
    Rationale: It is critical to ensure that the /etc/passwd file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file("/etc/passwd") do
    it { should exist }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/passwd") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/passwd") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should_not be_setgid }
  end
  describe file("/etc/passwd") do
    it { should_not be_sticky }
  end
  describe file("/etc/passwd") do
    it { should_not be_setuid }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/passwd") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/passwd") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.3_Ensure_permissions_on_etcshadow_are_configured" do
  title "Ensure permissions on /etc/shadow are configured"
  desc  "
    The /etc/shadow file is used to store the information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.
    
    Rationale: If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert the user accounts.
  "
  impact 1.0
  describe file("/etc/shadow") do
    it { should exist }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/shadow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/shadow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should_not be_setgid }
  end
  describe file("/etc/shadow") do
    it { should_not be_sticky }
  end
  describe file("/etc/shadow") do
    it { should_not be_setuid }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/shadow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.4_Ensure_permissions_on_etcgroup_are_configured" do
  title "Ensure permissions on /etc/group are configured"
  desc  "
    The /etc/group file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else.
    
    Rationale: The /etc/group file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs.
  "
  impact 1.0
  describe file("/etc/group") do
    it { should exist }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/group") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/group") do
    it { should_not be_setgid }
  end
  describe file("/etc/group") do
    it { should_not be_sticky }
  end
  describe file("/etc/group") do
    it { should_not be_setuid }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/group") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/group") do
    it { should be_writable.by "owner" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.5_Ensure_permissions_on_etcgshadow_are_configured" do
  title "Ensure permissions on /etc/gshadow are configured"
  desc  "
    The /etc/gshadow file is used to store the information about groups that is critical to the security of those accounts, such as the hashed password and other security information.
    
    Rationale: If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/gshadow file (such as group administrators) could also be useful to subvert the group.
  "
  impact 1.0
  describe file("/etc/gshadow") do
    it { should exist }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/gshadow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_setgid }
  end
  describe file("/etc/gshadow") do
    it { should_not be_sticky }
  end
  describe file("/etc/gshadow") do
    it { should_not be_setuid }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/gshadow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.6_Ensure_permissions_on_etcpasswd-_are_configured" do
  title "Ensure permissions on /etc/passwd- are configured"
  desc  "
    The /etc/passwd- file contains backup user account information.
    
    Rationale: It is critical to ensure that the /etc/passwd- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file("/etc/passwd-") do
    it { should exist }
  end
  describe file("/etc/passwd-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/passwd-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/passwd-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_setgid }
  end
  describe file("/etc/passwd-") do
    it { should_not be_sticky }
  end
  describe file("/etc/passwd-") do
    it { should_not be_setuid }
  end
  describe file("/etc/passwd-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/passwd-") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.7_Ensure_permissions_on_etcshadow-_are_configured" do
  title "Ensure permissions on /etc/shadow- are configured"
  desc  "
    The /etc/shadow- file is used to store backup information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.
    
    Rationale: It is critical to ensure that the /etc/shadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file("/etc/shadow-") do
    it { should exist }
  end
  describe file("/etc/shadow-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/shadow-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/shadow-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_setgid }
  end
  describe file("/etc/shadow-") do
    it { should_not be_sticky }
  end
  describe file("/etc/shadow-") do
    it { should_not be_setuid }
  end
  describe file("/etc/shadow-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/shadow-") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.8_Ensure_permissions_on_etcgroup-_are_configured" do
  title "Ensure permissions on /etc/group- are configured"
  desc  "
    The /etc/group- file contains a backup list of all the valid groups defined in the system.
    
    Rationale: It is critical to ensure that the /etc/group- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file("/etc/group-") do
    it { should exist }
  end
  describe file("/etc/group-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/group-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/group-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/group-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/group-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/group-") do
    it { should_not be_setgid }
  end
  describe file("/etc/group-") do
    it { should_not be_sticky }
  end
  describe file("/etc/group-") do
    it { should_not be_setuid }
  end
  describe file("/etc/group-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/group-") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.9_Ensure_permissions_on_etcgshadow-_are_configured" do
  title "Ensure permissions on /etc/gshadow- are configured"
  desc  "
    The /etc/gshadow- file is used to store backup information about groups that is critical to the security of those accounts, such as the hashed password and other security information.
    
    Rationale: It is critical to ensure that the /etc/gshadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file("/etc/gshadow-") do
    it { should exist }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/gshadow-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_setgid }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_sticky }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_setuid }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/gshadow-") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.10_Ensure_no_world_writable_files_exist" do
  title "Ensure no world writable files exist"
  desc  "
    Unix-based systems support variable settings to control access to files. World writable files are the least secure. See the chmod(2) man page for more information.
    
    Rationale: Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity.
  "
  impact 1.0
  world_writeable_files = command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -perm -0002 -type f ! -path \'/proc/*\' ! -path \'/sys/*\' -print 2>/dev/null').stdout.split(/\r?\n/)
  describe world_writeable_files do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.11_Ensure_no_unowned_files_or_directories_exist" do
  title "Ensure no unowned files or directories exist"
  desc  "
    Sometimes when administrators delete users from the password file they neglect to remove all files owned by those users from the system.
    
    Rationale: A new user who is assigned the deleted user's user ID or group ID may then end up \"owning\" these files, and thus have more access on the system than was intended.
  "
  impact 1.0
  file_no_user = command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nouser').stdout.split(/\r?\n/)
  describe file_no_user do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.12_Ensure_no_ungrouped_files_or_directories_exist" do
  title "Ensure no ungrouped files or directories exist"
  desc  "
    Sometimes when administrators delete users or groups from the system they neglect to remove all files owned by those users or groups.
    
    Rationale: A new user who is assigned the deleted user's user ID or group ID may then end up \"owning\" these files, and thus have more access on the system than was intended.
  "
  impact 1.0
  file_no_group = command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nogroup').stdout.split(/\r?\n/)
  describe file_no_group do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.13_Audit_SUID_executables" do
  title "Audit SUID executables"
  desc  "
    The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SUID program is to enable users to perform functions (such as changing their password) that require root privileges.
    
    Rationale: There are valid reasons for SUID programs, but it is important to identify and review such programs to ensure they are legitimate.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.1.14_Audit_SGID_executables" do
  title "Audit SGID executables"
  desc  "
    The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SGID program is to enable users to perform functions (such as changing their password) that require root privileges.
    
    Rationale: There are valid reasons for SGID programs, but it is important to identify and review such programs to ensure they are legitimate. Review the files returned by the action in the audit section and check to see if system binaries have a different md5 checksum than what from the package. This is an indication that the binary may have been replaced.
  "
  impact 0.0
  describe "No tests defined for this control" do
    skip "No tests defined for this control"
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.1_Ensure_password_fields_are_not_empty" do
  title "Ensure password fields are not empty"
  desc  "
    An account with an empty password field means that anybody may log in as that user without providing a password.
    
    Rationale: All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
  "
  impact 1.0
  describe shadow.where { user =~ /.+/ and password !~ /.+/ } do
    its("raw_data") { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.2_Ensure_no_legacy__entries_exist_in_etcpasswd" do
  title "Ensure no legacy \"+\" entries exist in /etc/passwd"
  desc  "
    The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on most systems, but may exist in files that have been imported from other platforms.
    
    Rationale: These entries may provide an avenue for attackers to gain privileged access on the system.
  "
  impact 1.0
  describe file("/etc/passwd") do
    its("content") { should_not match(/^\+:/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.3_Ensure_root_PATH_Integrity" do
  title "Ensure root PATH Integrity"
  desc  "
    The root user can execute any command on the system and could be fooled into executing programs unintentionally if the PATH is not set correctly.
    
    Rationale: Including the current working directory (.) or other writable directory in root 's executable path makes it likely that an attacker can gain superuser access by forcing an administrator operating as root to execute a Trojan horse program.
  "
  impact 1.0
  only_if { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe os_env('PATH').content.to_s.split(':') do
    it { should_not be_empty }
  end
  os_env('PATH').content.to_s.split(':').each do |entry|
    describe entry do
      it { should_not eq "" }
      it { should_not eq "." }
    end
  end
  os_env('PATH').content.to_s.split(':').each do |entry|
    describe file(entry) do
      it { should exist }
      it { should_not be_writable.by 'group' }
      it { should_not be_writable.by 'other' }
      its( 'uid' ) { should cmp 0 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.4_Ensure_no_legacy__entries_exist_in_etcshadow" do
  title "Ensure no legacy \"+\" entries exist in /etc/shadow"
  desc  "
    The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on most systems, but may exist in files that have been imported from other platforms.
    
    Rationale: These entries may provide an avenue for attackers to gain privileged access on the system.
  "
  impact 1.0
  describe file("/etc/shadow") do
    its("content") { should_not match(/^\+:/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.5_Ensure_no_legacy__entries_exist_in_etcgroup" do
  title "Ensure no legacy \"+\" entries exist in /etc/group"
  desc  "
    The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on most systems, but may exist in files that have been imported from other platforms.
    
    Rationale: These entries may provide an avenue for attackers to gain privileged access on the system.
  "
  impact 1.0
  describe file("/etc/group") do
    its("content") { should_not match(/^\+:/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.6_Ensure_root_is_the_only_UID_0_account" do
  title "Ensure root is the only UID 0 account"
  desc  "
    Any account with UID 0 has superuser privileges on the system.
    
    Rationale: This access must be limited to only the default root account and only from the system console. Administrative access must be through an unprivileged account using an approved mechanism as noted in Item 5.6 Ensure access to the su command is restricted.
  "
  impact 1.0
  describe file("/etc/passwd") do
    its("content") { should_not match(/^(?!root:)[^:]*:[^:]*:0/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.7_Ensure_users_home_directories_permissions_are_750_or_more_restrictive" do
  title "Ensure users' home directories permissions are 750 or more restrictive"
  desc  "
    While the system administrator can establish secure permissions for users' home directories, the users can easily override these.
    
    Rationale: Group or world-writable user home directories may enable malicious users to steal or modify other users' data or to gain another user's system privileges.
  "
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != '/sbin/nologin' }.where{ shell != '/usr/bin/nologin' }.where{ shell != '/bin/nologin' }.where{ shell != '/bin/false' }.homes.each do |homefolder|
    describe file(homefolder) do
      it { should exist }
      it { should be_directory }
      it { should be_executable.by('owner') }
      it { should_not be_executable.by('other') }
      it { should be_writable.by('owner') }
      it { should_not be_writable.by('group') }
      it { should_not be_writable.by('other') }
      it { should be_readable.by('owner') }
      it { should_not be_readable.by('other') }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.8_Ensure_users_own_their_home_directories" do
  title "Ensure users own their home directories"
  desc  "
    The user home directory is space defined for the particular user to set local environment variables and to store personal files.
    
    Rationale: Since the user is accountable for files stored in the user home directory, the user must be the owner of the directory.
  "
  impact 1.0
  homeslist = {}
  nologin = [ '/sbin/nologin', '/usr/bin/nologin', '/bin/nologin', '/bin/false' ]
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { ! nologin.include?(shell) }.users.each_with_index { |k,i| homeslist[k] = passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { ! nologin.include?(shell) }.homes[i] }
  homeslist.each do |user,homefolder|
    describe file(homefolder) do
      it { should exist }
      it { should be_directory }
      it { should be_owned_by user }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.9_Ensure_users_dot_files_are_not_group_or_world_writable" do
  title "Ensure users' dot files are not group or world writable"
  desc  "
    While the system administrator can establish secure permissions for users' \"dot\" files, the users can easily override these.
    
    Rationale: Group or world-writable user configuration files may enable malicious users to steal or modify other users' data or to gain another user's system privileges.
  "
  impact 1.0
  homeslist = {}
  nologin = [ '/sbin/nologin', '/usr/bin/nologin', '/bin/nologin', '/bin/false' ]
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { ! nologin.include?(shell) }.users.each_with_index { |k,i| homeslist[k] = passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { ! nologin.include?(shell) }.homes[i] }
  if homeslist.any?
    homeslist.each do |user,homefolder|
      dotfiles = command('ls -d ' + homefolder + '/.[A-Za-z0-9]*').stdout.split
      if !dotfiles.empty?
        dotfiles.each do |dotfile|
          if file(dotfile).exist?
            describe file(dotfile) do
              it { should exist }
              it { should be_owned_by user }
              it { should_not be_writable.by('group') }
              it { should_not be_writable.by('other') }
            end
          end
        end
      else
        describe dotfiles do
          it { should be_empty }
        end
      end
    end
  else
    describe homeslist do
      it { should be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.10_Ensure_no_users_have_.forward_files" do
  title "Ensure no users have .forward files"
  desc  "
    The .forward file specifies an email address to forward the user's mail to.
    
    Rationale: Use of the .forward file poses a security risk in that sensitive data may be inadvertently transferred outside the organization. The .forward file also poses a risk as it can be used to execute commands that may perform unintended actions.
  "
  impact 1.0
  homeslist = {}
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != '/sbin/nologin' }.where{ shell != '/usr/bin/nologin' }.where{ shell != '/bin/nologin' }.where{ shell != '/bin/false' }.raw_data.each {|u| homeslist[u["user"]] = u["home"] }
  if homeslist.any?
    homeslist.each do |user,homefolder|
      describe file(homefolder + '/.forward') do
        it { should_not exist }
      end
      hostbasedforwardfile = command('ls ' + homefolder + '/.forward.*').stdout.split
      if ! hostbasedforwardfile.empty?
        hostbasedforwardfile.each do |forwardfile|
          describe file(forwardfile) do
            it { should_not exist }
          end
        end
      else
        describe file(homefolder + '/.forward.example.com') do
          it { should_not exist }
        end
      end
      describe file(homefolder + '/.forward+') do
        it { should_not exist }
      end
    end
  else
    describe homeslist do
      it { should be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.11_Ensure_no_users_have_.netrc_files" do
  title "Ensure no users have .netrc files"
  desc  "
    The .netrc file contains data for logging into a remote host for file transfers via FTP.
    
    Rationale: The .netrc file presents a significant security risk since it stores passwords in unencrypted form. Even if FTP is disabled, user accounts may have brought over .netrc files from other systems which could pose a risk to those systems.
  "
  impact 1.0
  homeslist = {}
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { ! %w{ /sbin/nologin /usr/bin/nologin /bin/nologin /bin/false}.include?(shell) }.users.each_with_index {|k,i| homeslist[k] = passwd.where{ ! %w{ /sbin/nologin /usr/bin/nologin /bin/nologin /bin/false}.include?(shell) }.homes[i] }
  if homeslist.any?
    homeslist.each do |user,homefolder|
      describe file(homefolder + '/.netrc') do
        it { should_not exist }
      end
    end
  else
    describe homeslist do
      it { should be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.12_Ensure_users_.netrc_Files_are_not_group_or_world_accessible" do
  title "Ensure users' .netrc Files are not group or world accessible"
  desc  "
    While the system administrator can establish secure permissions for users' .netrc files, the users can easily override these.
    
    Rationale: .netrc files may contain unencrypted passwords that may be used to attack other systems.
  "
  impact 1.0
  homeslist = {}
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != '/sbin/nologin' }.where{ shell != '/usr/bin/nologin' }.where{ shell != '/bin/nologin' }.where{ shell != '/bin/false' }.raw_data.each {|u| homeslist[u["user"]] = u["home"] }
  if homeslist.any?
    homeslist.each do |user,homefolder|
      if file(homefolder + '/.netrc').exist?
        describe file(homefolder + '/.netrc') do
            it { should be_owned_by user }
            it { should be_writable.by('owner') }
            it { should_not be_writable.by('group') }
            it { should_not be_writable.by('other') }
            it { should be_readable.by('owner') }
            it { should_not be_readable.by('group') }
            it { should_not be_readable.by('other') }
            it { should be_executable.by('owner') }
            it { should_not be_executable.by('group') }
            it { should_not be_executable.by('other') }
        end
      else
        describe file(homefolder + '/.netrc') do
          it { should_not exist }
        end
      end
    end
  else
    describe homeslist do
      it { should be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.13_Ensure_no_users_have_.rhosts_files" do
  title "Ensure no users have .rhosts files"
  desc  "
    While no .rhosts files are shipped by default, users can easily create them.
    
    Rationale: This action is only meaningful if .rhosts support is permitted in the file /etc/pam.conf . Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf , they may have been brought over from other systems and could contain information useful to an attacker for those other systems.
  "
  impact 1.0
  homeslist = {}
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != '/sbin/nologin' }.where{ shell != '/usr/bin/nologin' }.where{ shell != '/bin/nologin' }.where{ shell != '/bin/false' }.raw_data.each {|u| homeslist[u["user"]] = u["home"] }
  if homeslist.any?
    homeslist.each do |user,homefolder|
      describe file(homefolder + '/.rhosts') do
        it { should_not exist }
      end
    end
  else
    describe homeslist do
      it { should be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.14_Ensure_all_groups_in_etcpasswd_exist_in_etcgroup" do
  title "Ensure all groups in /etc/passwd exist in /etc/group"
  desc  "
    Over time, system administration errors and changes can lead to groups being defined in /etc/passwd but not in /etc/group .
    
    Rationale: Groups defined in the /etc/passwd file but not in the /etc/group file pose a threat to system security since group permissions are not properly managed.
  "
  impact 1.0
  groupslist = {}
  passwd.uids.each_with_index {|k,i| groupslist[k] = passwd.gids[i] }
  if groupslist.any?
    groupslist.each do |uid,gid|
      describe etc_group do
        its('gids') { should include gid.to_i }
      end
    end
  else
    describe groupslist do
      it { should be_empty }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.15_Ensure_no_duplicate_UIDs_exist" do
  title "Ensure no duplicate UIDs exist"
  desc  "
    Although the useradd program will not let you create a duplicate User ID (UID), it is possible for an administrator to manually edit the /etc/passwd file and change the UID field.
    
    Rationale: Users must be assigned unique UIDs for accountability and to ensure appropriate access protections.
  "
  impact 1.0
  describe passwd() do
    its('uids') { should_not contain_duplicates }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.16_Ensure_no_duplicate_GIDs_exist" do
  title "Ensure no duplicate GIDs exist"
  desc  "
    Although the groupadd program will not let you create a duplicate Group ID (GID), it is possible for an administrator to manually edit the /etc/group file and change the GID field.
    
    Rationale: User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections.
  "
  impact 1.0
  describe etc_group() do
    its('gids') { should_not contain_duplicates }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.17_Ensure_no_duplicate_user_names_exist" do
  title "Ensure no duplicate user names exist"
  desc  "
    Although the useradd program will not let you create a duplicate user name, it is possible for an administrator to manually edit the /etc/passwd file and change the user name.
    
    Rationale: If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that username in /etc/passwd . For example, if \"test4\" has a UID of 1000 and a subsequent \"test4\" entry has a UID of 2000, logging in as \"test4\" will use UID 1000. Effectively, the UID is shared, which is a security problem.
  "
  impact 1.0
  describe passwd() do
    its('users') { should_not contain_duplicates }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.18_Ensure_no_duplicate_group_names_exist" do
  title "Ensure no duplicate group names exist"
  desc  "
    Although the groupadd program will not let you create a duplicate group name, it is possible for an administrator to manually edit the /etc/group file and change the group name.
    
    Rationale: If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that group in /etc/group . Effectively, the GID is shared, which is a security problem.
  "
  impact 1.0
  describe etc_group() do
    its('groups') { should_not contain_duplicates }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.19_Ensure_shadow_group_is_empty" do
  title "Ensure shadow group is empty"
  desc  "
    The shadow group allows system programs which require access the ability to read the /etc/shadow file. No users should be assigned to the shadow group.
    
    Rationale: Any users assigned to the shadow group would be granted read access to the /etc/shadow file. If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed passwords to break them. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert additional user accounts.
  "
  impact 1.0
  describe file("/etc/group") do
    its("content") { should_not match(/^shadow:[^:]*:[^:]*:[^:]+$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_6.2.20_Ensure_all_users_home_directories_exist" do
  title "Ensure all users' home directories exist"
  desc  "
    Users can be defined in /etc/passwd without a home directory or with a home directory that does not actually exist.
    
    Rationale: If the user's home directory does not exist or is unassigned, the user will be placed in \"/\" and will not be able to write any files or have local environment variables set.
  "
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != '/sbin/nologin' }.where{ shell != '/usr/bin/nologin' }.where{ shell != '/bin/nologin' }.where{ shell != '/bin/false' }.homes.each do |homefolder|
    describe file(homefolder) do
      it {should exist }
      it {should be_directory }
    end
  end
end