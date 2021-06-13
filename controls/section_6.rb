# controls/section_6.rb
# encoding: UTF-8

control "6.1.1_Audit_system_file_permissions" do
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

control "6.1.2_Ensure_permissions_on_etcpasswd_are_configured" do
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

control "6.1.3_Ensure_permissions_on_etcshadow_are_configured" do
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

control "6.1.4_Ensure_permissions_on_etcgroup_are_configured" do
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

control "6.1.5_Ensure_permissions_on_etcgshadow_are_configured" do
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

control "6.1.6_Ensure_permissions_on_etcpasswd-_are_configured" do
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

control "6.1.7_Ensure_permissions_on_etcshadow-_are_configured" do
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

control "6.1.8_Ensure_permissions_on_etcgroup-_are_configured" do
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

control "6.1.9_Ensure_permissions_on_etcgshadow-_are_configured" do
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

control "6.1.10_Ensure_no_world_writable_files_exist" do
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

control "6.1.11_Ensure_no_unowned_files_or_directories_exist" do
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

control "6.1.12_Ensure_no_ungrouped_files_or_directories_exist" do
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

control "6.1.13_Audit_SUID_executables" do
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

control "6.1.14_Audit_SGID_executables" do
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

control "6.2.1_Ensure_password_fields_are_not_empty" do
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

control "6.2.2_Ensure_no_legacy__entries_exist_in_etcpasswd" do
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

control "6.2.3_Ensure_root_PATH_Integrity" do
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

control "6.2.4_Ensure_no_legacy__entries_exist_in_etcshadow" do
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

control "6.2.5_Ensure_no_legacy__entries_exist_in_etcgroup" do
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

control "6.2.6_Ensure_root_is_the_only_UID_0_account" do
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

control "6.2.7_Ensure_users_home_directories_permissions_are_750_or_more_restrictive" do
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

control "6.2.8_Ensure_users_own_their_home_directories" do
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

control "6.2.9_Ensure_users_dot_files_are_not_group_or_world_writable" do
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

control "6.2.10_Ensure_no_users_have_.forward_files" do
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

control "6.2.11_Ensure_no_users_have_.netrc_files" do
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

control "6.2.12_Ensure_users_.netrc_Files_are_not_group_or_world_accessible" do
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

control "6.2.13_Ensure_no_users_have_.rhosts_files" do
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

control "6.2.14_Ensure_all_groups_in_etcpasswd_exist_in_etcgroup" do
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

control "6.2.15_Ensure_no_duplicate_UIDs_exist" do
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

control "6.2.16_Ensure_no_duplicate_GIDs_exist" do
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

control "6.2.17_Ensure_no_duplicate_user_names_exist" do
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

control "6.2.18_Ensure_no_duplicate_group_names_exist" do
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

control "6.2.19_Ensure_shadow_group_is_empty" do
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

control "6.2.20_Ensure_all_users_home_directories_exist" do
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
