# controls/section_3.rb
# encoding: UTF-8

control "3.1.1_Ensure_IP_forwarding_is_disabled" do
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

control "3.1.2_Ensure_packet_redirect_sending_is_disabled" do
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

control "3.2.1_Ensure_source_routed_packets_are_not_accepted" do
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

control "3.2.2_Ensure_ICMP_redirects_are_not_accepted" do
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

control "3.2.3_Ensure_secure_ICMP_redirects_are_not_accepted" do
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

control "3.2.4_Ensure_suspicious_packets_are_logged" do
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

control "3.2.5_Ensure_broadcast_ICMP_requests_are_ignored" do
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

control "3.2.6_Ensure_bogus_ICMP_responses_are_ignored" do
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

control "3.2.7_Ensure_Reverse_Path_Filtering_is_enabled" do
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

control "3.2.8_Ensure_TCP_SYN_Cookies_is_enabled" do
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

control "3.2.9_Ensure_IPv6_router_advertisements_are_not_accepted" do
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

control "3.3.1_Ensure_DCCP_is_disabled" do
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

control "3.3.2_Ensure_SCTP_is_disabled" do
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

control "3.3.3_Ensure_RDS_is_disabled" do
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

control "3.3.4_Ensure_TIPC_is_disabled" do
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

control "3.4.1.1_Ensure_a_Firewall_package_is_installed" do
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

control "3.4.2.1_Ensure_firewalld_service_is_enabled_and_running" do
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

control "3.4.2.2_Ensure_iptables_is_not_enabled" do
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

control "3.4.2.3_Ensure_nftables_is_not_enabled" do
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

control "3.4.2.4_Ensure_default_zone_is_set" do
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

control "3.4.2.5_Ensure_network_interfaces_are_assigned_to_appropriate_zone" do
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

control "3.4.2.6_Ensure_unnecessary_services_and_ports_are_not_accepted" do
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

control "3.4.3.1_Ensure_iptables_are_flushed" do
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

control "3.4.3.2_Ensure_a_table_exists" do
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

control "3.4.3.3_Ensure_base_chains_exist" do
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

control "3.4.3.4_Ensure_loopback_traffic_is_configured" do
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

control "3.4.3.5_Ensure_outbound_and_established_connections_are_configured" do
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

control "3.4.3.6_Ensure_default_deny_firewall_policy" do
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

control "3.4.3.7_Ensure_nftables_service_is_enabled" do
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

control "3.4.3.8_Ensure_nftables_rules_are_permanent" do
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

control "3.4.4.1.1_Ensure_default_deny_firewall_policy" do
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

control "3.4.4.1.2_Ensure_loopback_traffic_is_configured" do
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

control "3.4.4.1.3_Ensure_outbound_and_established_connections_are_configured" do
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

control "3.4.4.1.4_Ensure_firewall_rules_exist_for_all_open_ports" do
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

control "3.4.4.2.1_Ensure_IPv6_default_deny_firewall_policy" do
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

control "3.4.4.2.2_Ensure_IPv6_loopback_traffic_is_configured" do
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

control "3.4.4.2.3_Ensure_IPv6_outbound_and_established_connections_are_configured" do
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

control "3.4.4.2.4_Ensure_IPv6_firewall_rules_exist_for_all_open_ports" do
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

control "3.5_Ensure_wireless_interfaces_are_disabled" do
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

control "3.6_Disable_IPv6" do
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
