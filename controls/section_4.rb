# controls/section_4.rb
# encoding: UTF-8

control "4.1.1.1_Ensure_auditd_is_installed" do
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

control "4.1.1.2_Ensure_auditd_service_is_enabled" do
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

control "4.1.1.3_Ensure_auditing_for_processes_that_start_prior_to_auditd_is_enabled" do
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

control "4.1.1.4_Ensure_audit_backlog_limit_is_sufficient" do
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

control "4.1.2.1_Ensure_audit_log_storage_size_is_configured" do
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

control "4.1.2.2_Ensure_audit_logs_are_not_automatically_deleted" do
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

control "4.1.2.3_Ensure_system_is_disabled_when_audit_logs_are_full" do
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

control "4.1.3_Ensure_changes_to_system_administration_scope_sudoers_is_collected" do
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

control "4.1.4_Ensure_login_and_logout_events_are_collected" do
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

control "4.1.5_Ensure_session_initiation_information_is_collected" do
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

control "4.1.6_Ensure_events_that_modify_date_and_time_information_are_collected" do
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

control "4.1.7_Ensure_events_that_modify_the_systems_Mandatory_Access_Controls_are_collected" do
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

control "4.1.8_Ensure_events_that_modify_the_systems_network_environment_are_collected" do
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

control "4.1.9_Ensure_discretionary_access_control_permission_modification_events_are_collected" do
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

control "4.1.10_Ensure_unsuccessful_unauthorized_file_access_attempts_are_collected" do
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

control "4.1.11_Ensure_events_that_modify_usergroup_information_are_collected" do
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

control "4.1.12_Ensure_successful_file_system_mounts_are_collected" do
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

control "4.1.13_Ensure_use_of_privileged_commands_is_collected" do
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

control "4.1.14_Ensure_file_deletion_events_by_users_are_collected" do
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

control "4.1.15_Ensure_kernel_module_loading_and_unloading_is_collected" do
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

control "4.1.16_Ensure_system_administrator_actions_sudolog_are_collected" do
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

control "4.1.17_Ensure_the_audit_configuration_is_immutable" do
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

control "4.2.1.1_Ensure_rsyslog_is_installed" do
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

control "4.2.1.2_Ensure_rsyslog_Service_is_enabled" do
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

control "4.2.1.3_Ensure_rsyslog_default_file_permissions_configured" do
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

control "4.2.1.4_Ensure_logging_is_configured" do
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

control "4.2.1.5_Ensure_rsyslog_is_configured_to_send_logs_to_a_remote_log_host" do
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

control "4.2.1.6_Ensure_remote_rsyslog_messages_are_only_accepted_on_designated_log_hosts." do
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

control "4.2.2.1_Ensure_journald_is_configured_to_send_logs_to_rsyslog" do
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

control "4.2.2.2_Ensure_journald_is_configured_to_compress_large_log_files" do
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

control "4.2.2.3_Ensure_journald_is_configured_to_write_logfiles_to_persistent_disk" do
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

control "4.2.3_Ensure_permissions_on_all_logfiles_are_configured" do
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

control "4.3_Ensure_logrotate_is_configured" do
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
