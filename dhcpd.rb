#!/usr/bin/ruby

# (c) Aki Tuomi 2011 - See license. 

require 'rubygems'
require 'log4r'
require 'log4r/outputter/syslogoutputter'
require 'daemons'
require 'socket'
require 'net-dhcp'
require 'ipaddr'

include Log4r

ip = '1.2.3.4'
networks = ['10.255.0.0/24', '1.2.3.0/24']

class DhcpServer
  def initialize(ip, networks)
    @log = Logger.new 'dhcpd'
    @log.outputters = SyslogOutputter.new('dhcpd', :logopt => 0x1, :facility => 'LOG_DAEMON')
    #@log.outputters = Outputter.stderr
    @log.outputters[0].formatter = PatternFormatter.new(:pattern => "%M")
    @ip = ip
    @networks = networks
  end

  def valid?(ip)
    return true if ip == "0.0.0.0"
    @networks.each do |net|
      tmp,cidr = net.split "/"
      ip0 = IPAddr.new(tmp).mask(cidr).to_s
      ip1 = IPAddr.new(ip).mask(cidr).to_s
      return true if ip0 == ip1
    end
    return false
  end

  def options(msg, msgtype)
     # extract some, replace with ours
     opts = []
     msg.options.each do |opt|
       drop = false
       [DHCP::MessageTypeOption, DHCP::RouterOption, DHCP::IPAddressLeaseTimeOption, 
        DHCP::SubnetMaskOption, DHCP::DomainNameServerOption, DHCP::ServerIdentifierOption, 
        DHCP::ParameterRequestListOption, DHCP::RequestedIPAddressOption].each do |iopt|
         if opt.is_a?(iopt)
           drop = true
           break
         end
       end
       next if drop
       opts << opt
     end

     opts << DHCP::MessageTypeOption.new(:payload => [msgtype])
     opts << DHCP::RouterOption.new(:payload => IPAddr.new(msg.giaddr, Socket::AF_INET).to_s.split('.').map { |i| i.to_i })
     opts << DHCP::IPAddressLeaseTimeOption.new
     opts << DHCP::SubnetMaskOption.new(:payload => [255, 255, 255, 254])
     opts << DHCP::DomainNameServerOption.new(:payload => [195, 10, 132, 196])
     opts << DHCP::DomainNameServerOption.new(:payload => [195, 10, 132, 203])
     opts << DHCP::ServerIdentifierOption.new(:payload => IPAddr.new(@ip).to_s.split('.').map { |i| i.to_i })
 
     return opts
  end

  def discover2offer(msg)
    offer = DHCP::Offer.new
    offer.yiaddr = msg.giaddr+1
    offer.xid = msg.xid
    offer.giaddr = msg.giaddr
    offer.chaddr = msg.chaddr
    offer.options = self.options(msg, 2)

    return offer
  end

  def request2ack(msg)
    ack = DHCP::ACK.new
    ack.yiaddr = msg.giaddr+1
    ack.xid = msg.xid
    ack.giaddr = msg.giaddr
    ack.chaddr = msg.chaddr
    ack.options = self.options(msg, 5)

    return ack
  end

  def run
    @log.info "TDC DHCP started - Binding to port 67"

    # socket code
    @socket  = UDPSocket.new
    @socket.bind(@ip, 67)

    loop do 
      # yarr..
      read_array = Kernel.select [@socket], nil, nil, 1
      unless read_array.nil? 
         # process message
         begin
            data, addr = @socket.recvfrom(1500)
            imsg = DHCP::Message.from_udp_payload(data)
         rescue 
            next
         end

         if imsg.nil?
           @log.info "Received garbled data from #{addr[2]}"
           next
         end

         giaddr = IPAddr.new(imsg.giaddr, Socket::AF_INET).to_s
         ciaddr = IPAddr.new(imsg.ciaddr, Socket::AF_INET).to_s
         
         unless giaddr == addr[2] 
           @log.warn "Received #{imsg.class} from #{addr[2]}, but giaddr is #{giaddr} - ignoring packet"
           next
         end

         @log.info "Received #{imsg.class} from #{giaddr}, client: #{ciaddr} HW: #{imsg.chaddr}"

         unless valid?(giaddr) and valid?(ciaddr)
           @log.warn "Unauthorized source address - dropping request"
           next 
         end

         if imsg.is_a?(DHCP::Discover)
           omsg = discover2offer(imsg)
         elsif imsg.is_a?(DHCP::Request)
           omsg = request2ack(imsg)
         end

         @log.debug "Sending #{omsg.class} with client address #{IPAddr.new(omsg.yiaddr, Socket::AF_INET).to_s} to #{giaddr}"
         @socket.send omsg.pack, 0, addr[2], addr[1]
      end
    end
  end
end

Daemons.run_proc('dhcpd') do 
  app = DhcpServer.new(ip,networks)
  app.run
end
