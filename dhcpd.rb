#!/usr/bin/ruby

# (c) Aki Tuomi 2011 - See license. 
# chkconfig for RedHat Linux...
#
# chkconfig: 345 99 00
# description: Controls the PE-DHCP daemon
# processname: pe-dhcpd

# chkconfig/insserv for SUSE Linux...
### BEGIN INIT INFO
# Provides: pe-dhcpd
# Required-Start: $all
# Should-Start:
# X-UnitedLinux-Should-Start:
# Required-Stop:
# Default-Start: 3 5
# Default-Stop:
# Short-Description: pe-dhcpd
# Description: Controls the PE-DHCP daemon
### END INIT INFO

# makes things work when installed as service
if File.symlink?(__FILE__) 
  $:.push File.dirname(File.readlink(__FILE__))
else
  $:.push File.dirname(__FILE__)
end

require 'rubygems'
require 'log4r'
require 'log4r/outputter/syslogoutputter'
require 'daemons'
require 'socket'
require 'ipaddr'
require 'lib/options'
require 'lib/bootpacket'

include Log4r
include PeDHCP

# set to nil for guessing, otherwise specify
ip = nil

class DhcpServer
  def initialize(ip)
    ip = guess_my_ip if ip.nil?
    @ip = ip
  end

  def guess_my_ip
    UDPSocket.open {|s| s.connect("8.8.8.8", 1); s.addr.last }
  end
 
  def set_options(msg)
    requested = msg.get_option(55)

    # kill parameter request list and requested ip address
    msg.remove_option(55)
    msg.remove_option(50)

    # overwrite/add required options
    msg.set_option(DHCPServerIdentifierOption.new(@ip))
    msg.set_option(SubnetMaskOption.new("255.255.255.254"))
    msg.set_option(RouterOption.new(IPAddr.new(msg.giaddr, Socket::AF_INET).to_s))
    msg.set_option(DomainNameServerOption.new(["195.10.132.196", "195.10.132.203"]))
    msg.set_option(IPAddressLeaseTimeOption.new(0xA8C0))
    msg.set_option(NetworkTimeProtocolServersOption.new(["195.10.132.196", "195.10.132.203"]))
    msg.set_option(RebindingTimeValueOption.new(0x93A8))
    msg.set_option(RenewalTimeValueOption.new(0x5460))

    # kill anything that wasn't on parameter request list
    unless requested.nil?
       new_options = []
       keep = requested.get
       msg.options.each do |option|
         # retain messagetypeoption even if it was not asked for...
         new_options << option if keep.include?(option.key) or option.key == 53 or option.key == 82
       end
       msg.options = new_options
    end
  end

  def request2reply(msg, type, flags)
    reply = msg.clone
    reply.yiaddr = reply.giaddr+1
    reply.op = BootPacket::REPLY
    reply.type = type
    reply.flags = flags
    set_options(reply)
    return reply
  end

  def run
    $log.info "TDC DHCP started - Binding to #{@ip}:67"

     # socket code
    BasicSocket.do_not_reverse_lookup = true
    @socket = UDPSocket.new
    @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
    @socket.bind(@ip, 67)

    # drop privs
    Process::Sys.setresgid(99,99,99)
    Process::Sys.setresuid(99,99,99)

    loop do 
      read_array = Kernel.select [@socket], nil, nil, 10
      unless read_array.nil? 
         # process message
         begin
            data, addr = @socket.recvfrom(1500)
            imsg = BootPacket.new(data)
         rescue Exception => e
            $log.error "Processing error: #{e}\n#{e.backtrace.join("\n")}"
	    $log.debug "Dumping message packet for debug"
            str = data.bytes.map { |c| sprintf("%02x", c.to_i) }.join(' ');
            $log.debug str
            next
         end

         if imsg.valid? == false
           imsg.type = MessageTypeOption::REQUEST
         end

         $log.info "Received #{imsg.type.type_s} from #{imsg.chaddr_s} via #{imsg.giaddr_s}"
         $log.debug imsg.to_s

         case imsg.type.type
            when MessageTypeOption::DISCOVER
              omsg = request2reply(imsg, MessageTypeOption::OFFER, 0x8000)
            when MessageTypeOption::REQUEST
              omsg = request2reply(imsg, MessageTypeOption::ACK, imsg.flags)
            else
              next
         end

         $log.info "Sending #{omsg.type.type_s} to #{imsg.yiaddr_s} #{imsg.chaddr_s} via #{imsg.giaddr_s}"
         $log.debug omsg.to_s

         # send the packet back where it came from
         @socket.send omsg.pack, 0, addr[3], addr[1]
      end
    end
  end
end

Daemons.run_proc('pe-dhcpd', { :dir_mode => :system }) do 
  begin
    $log = Logger.new 'dhcpd'
    if Daemons.controller.options[:ontop] 
      $log = Logger.new 'dhcpd'
      $log.outputters = Outputter.stderr
      $log.outputters[0].formatter = PatternFormatter.new(:pattern => "%d [%l]: %m")
      $log.level = DEBUG
    else
      $log.outputters = SyslogOutputter.new('dhcpd', :logopt => 0x1, :facility => 'LOG_DAEMON')
      $log.outputters[0].formatter = PatternFormatter.new(:pattern => "%M")
      $log.level = INFO
    end
    app = DhcpServer.new(ip)
    app.run
  rescue Interrupt => e 
    $log.warn "Shutdown complete"
    # do nothing
  end 
end
