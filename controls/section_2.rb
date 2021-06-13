# controls/section_2.rb
# encoding: UTF-8

control "2.1.1_Ensure_xinetd_is_not_installed" do
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

control "2.2.1.1_Ensure_time_synchronization_is_in_use" do
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

control "2.2.1.2_Ensure_chrony_is_configured" do
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

control "2.2.2_Ensure_X_Window_System_is_not_installed" do
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

control "2.2.3_Ensure_rsync_service_is_not_enabled" do
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

control "2.2.4_Ensure_Avahi_Server_is_not_enabled" do
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

control "2.2.5_Ensure_SNMP_Server_is_not_enabled" do
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

control "2.2.6_Ensure_HTTP_Proxy_Server_is_not_enabled" do
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

control "2.2.7_Ensure_Samba_is_not_enabled" do
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

control "2.2.8_Ensure_IMAP_and_POP3_server_is_not_enabled" do
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

control "2.2.9_Ensure_HTTP_server_is_not_enabled" do
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

control "2.2.10_Ensure_FTP_Server_is_not_enabled" do
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

control "2.2.11_Ensure_DNS_Server_is_not_enabled" do
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

control "2.2.12_Ensure_NFS_is_not_enabled" do
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

control "2.2.13_Ensure__RPC_is_not_enabled" do
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

control "2.2.14_Ensure_LDAP_server_is_not_enabled" do
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

control "2.2.15_Ensure_DHCP_Server_is_not_enabled" do
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

control "2.2.16_Ensure_CUPS_is_not_enabled" do
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

control "2.2.17_Ensure_NIS_Server_is_not_enabled" do
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

control "2.2.18_Ensure_mail_transfer_agent_is_configured_for_local-only_mode" do
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

control "2.3.1_Ensure_NIS_Client_is_not_installed" do
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

control "2.3.2_Ensure_telnet_client_is_not_installed" do
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

control "2.3.3_Ensure_LDAP_client_is_not_installed" do
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