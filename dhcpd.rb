#!/usr/bin/ruby

# (c) Aki Tuomi 2011 - See license. 

## CONFIGURATION ##
# set to nil for guessing, otherwise specify

ip = nil
DNS_SERVERS = %w{ 195.10.132.196 195.10.132.203 }
NTP_SERVERS = %w{ 195.10.132.196 195.10.132.203 }
LEASE_TIME = 86400
REBIND_TIME = 37800
RENEWAL_TIME = 28800
# You can filter here any MAC masks you do not wish to serve
# Supports 00-00-00-00-00-00, 00:00:00:00:00:00, 0000.0000.0000
# and you can add /prefix to create a mask. Prefix can be from 0 to 48
# /48 is single address (default if omitted), and 0 is everything
BLACKIST_MACS = %w{ b0:0b:00:00:00:00/24 test.addr.0000/40 }

## END CONFIGURATION ##

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
    msg.set_option(SubnetMaskOption.new("255.255.255.254"))
    msg.set_option(RouterOption.new(IPAddr.new(msg.giaddr, Socket::AF_INET).to_s))
    msg.set_option(DomainNameServerOption.new(DNS_SERVERS))
    msg.set_option(IPAddressLeaseTimeOption.new(LEASE_TIME))
    msg.set_option(NetworkTimeProtocolServersOption.new(NTP_SERVERS))
    msg.set_option(RebindingTimeValueOption.new(REBIND_TIME))
    msg.set_option(RenewalTimeValueOption.new(RENEWAL_TIME))
    msg.set_option(DHCPServerIdentifierOption.new(@ip))

    # kill anything that wasn't on parameter request list
    unless requested.nil?
       new_options = []
       keep = requested.get + [51,53,54,60,61,82]
       msg.options.each do |option|
         # retain messagetypeoption even if it was not asked for...
         if keep.include?(option.key) 
           new_options << option
         else 
           $log.debug "Dropping #{option.class} as it's not wanted"
         end
       end
       msg.options = new_options
    end

    return msg
  end

  def request2reply(msg, type, flags)
    reply = msg.clone
    reply.yiaddr = reply.giaddr+1
    reply.op = BootPacket::REPLY
    reply.flags = flags
    reply = set_options(reply)
    reply.type = type
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
            str = data.bytes.map { |c| "%02x" % [c.to_i] }.join(' ');
            $log.debug str
            next
         end

         if imsg.valid? == false
           imsg.type = MessageTypeOption::REQUEST
         end

         $log.info "Received #{imsg.type.type_s} from #{imsg.ciaddr_s} #{imsg.chaddr_s} via #{imsg.giaddr_s}"
         $log.debug imsg.to_s

         imsg.giaddr = imsg.ciaddr-1 if imsg.giaddr == 0 and imsg.ciaddr != 0

         if imsg.giaddr == 0 
           $log.info "Cannot handle packet with no giaddr"
           next
         end

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
    $log.outputters = SyslogOutputter.new('dhcpd', :logopt => 0x1, :facility => 'LOG_DAEMON')
    $log.outputters[0].formatter = PatternFormatter.new(:pattern => "%M")
    $log.level = INFO

    if Daemons.controller.options[:ontop] 
      $log = Logger.new 'dhcpd'
      $log.outputters = Outputter.stderr
      $log.outputters[1].formatter = PatternFormatter.new(:pattern => "%d [%l]: %m")
      $log.level = DEBUG
    end

    app = DhcpServer.new(ip)
    app.run
  rescue Interrupt => e 
    $log.warn "Shutdown complete"
    # do nothing
  end 
end
