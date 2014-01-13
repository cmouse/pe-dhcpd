#!/usr/bin/ruby

# (c) Aki Tuomi 2011 - See license.

require 'rubygems'
require 'bundler/setup'
require 'log4r'
require 'log4r/outputter/syslogoutputter'
require 'daemons'
require 'socket'
require 'ipaddr'

require 'pe-dhcpd/options'
require 'pe-dhcpd/bootpacket'
require 'pe-dhcpd/macfilter'

module PeDHCPd

  class DhcpServer
    def log=
      @log = log
    end
  
    def log
      @log
    end
  
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
      if YIADDR_POLICY_30_OR_31_MASK
         if msg.giaddr.odd?
            msg.set_option(SubnetMaskOption.new('255.255.255.252'))
         else
            msg.set_option(SubnetMaskOption.new('255.255.255.254'))
         end
      else
         msg.set_option(SubnetMaskOption.new(SUBNET_MASK))
      end
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
             log.debug "Dropping #{option.class} as it's not wanted"
           end
         end
         msg.options = new_options
      end
  
      return msg
    end
  
    def giaddr2yiaddr(addr, mask)
      if (addr.odd? and mask.to_bits == 30) or (not addr.odd? and mask.to_bits == 31)
        addr += 1
      elsif [31, 30].include? mask.to_bits
        addr -= 1
      else
        addr += YIADDR_POLICY
      end
    end
  
  
    def request2reply(msg, type, flags)
      reply = msg.clone
      reply.op = BootPacket::REPLY
      reply.flags = flags
      reply = set_options(reply)
      if YIADDR_POLICY_30_OR_31_MASK
        reply.yiaddr = reply.giaddr + 1
      else
        reply.yiaddr = giaddr2yiaddr(reply.giaddr, reply.get_option(1))
      end
      reply.type = type
      return reply
    end
  
    def run
      log.info "TDC DHCP started - Binding to #{@ip}:67"
  
       # socket code
      BasicSocket.do_not_reverse_lookup = true
      @socket = UDPSocket.new
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      @socket.bind(@ip, 67)
  
      # drop privs
      Process::Sys.setresgid(99,99,99)
      Process::Sys.setresuid(99,99,99)
  
      # generate MacFilter
      filter = MacFilterList.new
      BLACKLIST_MACS.each do |mac|
        filter << mac
      end 
  
      loop do 
        read_array = Kernel.select [@socket], nil, nil, 10
        unless read_array.nil? 
           # process message
           begin
              data, addr = @socket.recvfrom(1500)
              imsg = BootPacket.new(data)
           rescue Exception => e
              log.error "Processing error: #{e}\n#{e.backtrace.join("\n")}"
              log.debug "Dumping message packet for debug"
              str = data.bytes.map { |c| "%02x" % [c.to_i] }.join(' ');
              log.debug str
              next
           end
  
           if imsg.valid? == false
             imsg.type = MessageTypeOption::REQUEST
           end
  
           if filter.include? imsg.chaddr 
             log.info "Ignoring DHCP from #{imsg.chaddr_s} due to blacklist"
             next
           end
  
           log.info "Received #{imsg.type.type_s} from #{imsg.ciaddr_s} #{imsg.chaddr_s} via #{imsg.giaddr_s}"
           log.debug imsg.to_s
  
           imsg.giaddr = imsg.ciaddr-1 if imsg.giaddr == 0 and imsg.ciaddr != 0
  
           if imsg.giaddr == 0 
             log.info "Cannot handle packet with no giaddr"
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
  
           log.info "Sending #{omsg.type.type_s} to #{imsg.yiaddr_s} #{imsg.chaddr_s} via #{imsg.giaddr_s}"
           log.debug omsg.to_s
  
           # send the packet back where it came from
           @socket.send omsg.pack, 0, addr[3], addr[1]
        end
      end
    end
  end
end
