#!/usr/bin/ruby

# (c) Aki Tuomi 2011 - See license. 

require 'rubygems'
require 'log4r'
require 'log4r/outputter/syslogoutputter'
require 'daemons'
require 'socket'
require 'ipaddr'
include Log4r

ip = '1.2.3.4'
networks = ['10.255.0.0/24', '1.2.3.0/24']

class BootOption
  attr_accessor :key, :len, :value

  def initialize(*args)
    if args.size == 3
      @key = args.shift
      @len = args.shift
      @value = args.shift
    elsif args.size == 1
      build args[0]
    elsif args.size == 0
      @key = 0
      @len = 0 
      @value = ""
     else
      raise ArgumentError.new
    end
  end

  def pack 
    return [@key,@len].pack('CC') + @value if (@value.is_a?(String))
    return ([@key,@len]+@value).pack('CC*') if (@value.is_a?(Array))
  end

  def to_s
    str = "Option #{@key} with #{@len} bytes of data: "
    str += @value.unpack("C*").each { |c| sprintf("02x", c) }.join(" ")
    return str
  end
end

class SubnetMaskOption < BootOption
 def build(value)
   @key = 1 
   @len = 4
   if value.is_a?(Array)
     @value = value.pack("CCCC")
   elsif value.is_a?(String)
     @value = value.split(".").map { |c| c.to_i }.pack("CCCC")
   elsif value.is_a?(Fixnum)
     @value = value
   end
 end
 
 def to_s
   str = "Subnet mask = "
   str += @value.unpack("CCCC").join('.')
   return str
 end
end

class RouterOption < BootOption
 def build(value)
   @key = 3
   @len = 4
   if value.is_a?(Array)
     @value = value.pack("CCCC")
   elsif value.is_a?(String)
     @value = value.split(".").map { |c| c.to_i }.pack("CCCC")
   end
 end

 def to_s
   str = "Router = "
   str += @value.unpack("CCCC").join('.')
   return str
 end
end

class DomainNameServerOption < BootOption
  def build(value)
    @key = 6
    if value.is_a?(String)
       @value = value.split(".").map { |c| c.to_i }.pack("CCCC")
       @len = 4
    elsif value.is_a?(Array)
       @value = ""
       @len = value.size * 4
       value.each do |v|
          @value += v.split(".").map { |c| c.to_i }.pack("CCCC")
       end
    end
  end

  def to_s
    # unpack all names
    tmp1 = @value.unpack("C*")
    return "Domain Name Servers = invalid value (data not congruent to 4)" unless (tmp1.size % 4) == 0
    str = "Domain Name Servers = "
    tmp2 = []
    while tmp1.size > 0 
     tmp2 << tmp1.shift(4).join('.')
    end
    return tmp2.join("\n")
  end
end

class RequestedIPAddressOption < BootOption
 def build(value)
   @key = 50
   @len = 4
   if value.is_a?(Array)
     @value = value.pack("CCCC")
   elsif value.is_a?(String)
     @value = value.split(".").map { |c| c.to_i }.pack("CCCC")
   end
 end

 def to_s
   str = "Requested IP Address = "
   str += @value.unpack("CCCC").join('.')
   return str
 end
end

class DHCPServerIdentifierOption < BootOption
 def build(value)
   @key = 54
   @len = 4
   if value.is_a?(Array)
     @value = value.pack("CCCC")
   elsif value.is_a?(String)
     @value = value.split(".").map { |c| c.to_i }.pack("CCCC")
   end
 end

 def to_s
   str = "Router = "
   str += @value.unpack("CCCC").join('.')
   return str
 end
end

class IPAddressLeaseTimeOption < BootOption
   def build(value)
     @key = 51
     @len = 4
     @value = [value].pack('N').unpack('CCCC')
   end

   def to_s
     return "IP Address Lease Time = " + @value.pack('CCCC').unpack('N').to_s + " seconds"
   end
end

class ParameterRequestListOption < BootOption
  def build(value)
    @key = 55
    @len = value.size
    @value = value.pack("C*")
  end

  def to_s 
    str = "Parameter Request List = "
    str += @value.unpack("C*").join(",")
    return str
  end
end

class MessageTypeOption < BootOption
  DISCOVER=1
  OFFER=2
  REQUEST=3
  DECLINE=4
  ACK=5
  NAK=6
  RELEASE=7
  INFORM=8
  FORCERENEW=9
  LEASEQUERY=10
  LEASEUNASSIGNED=11
  LEASEUNKNOWN=12
  LEASEACTIVE=13

  def build(value)
    @key = 53
    @len = 1
    @value = [value].pack("C")
  end

  def type=(value)
    @value = [value].pack("C")
  end

  def type
    return @value.unpack("C")[0]
  end

  def to_s
    case type
      when DISCOVER
        return "DHCP Message Type = Discover"
      when OFFER
        return "DHCP Message Type = Offer"
      when REQUEST
        return "DHCP Message Type = Request"
      when DECLINE
        return "DHCP Message Type = Decline"
      when ACK
        return "DHCP Message Type = ACK"
      when NAK
        return "DHCP Message Type = NAK"
      when RELEASE
        return "DHCP Message Type = Release"
      when INFORM
        return "DHCP Message Type = Inform"
      when FORCERENEW
        return "DHCP Message Type = ForceRenew"
      when LEASEQUERY
        return "DHCP Message Type = LeaseQuery"
      when LEASEUNASSIGNED
        return "DHCP Message Type = LeaseUnassigned"
      when LEASEUNKNOWN
        return "DHCP Message Type = LeaseUnknown"
      when LEASEACTIVE
        return "DHCP Message Type = LeaseActive"
    end
    return "DHCP Message Type = Unknown"
  end
end

class BootPacket
  REQUEST = 1
  REPLY = 2

  BOOTOPTIONS = {
        1 => SubnetMaskOption,
        3 => RouterOption,
        6 => DomainNameServerOption,
        50 => RequestedIPAddressOption,
        51 => IPAddressLeaseTimeOption, 
	53 => MessageTypeOption,
        54 => DHCPServerIdentifierOption,
        55 => ParameterRequestListOption
  }	

  def initialize
    @params = {
      :op => 0x0,
      :htype => 0x0,
      :hlen => 0x0,
      :hops => 0x0,
      :xid => 0x0,
      :secs => 0x0,
      :flags => 0x0,	
      :ciaddr => 0x0,
      :yiaddr => 0x0,
      :siaddr => 0x0,
      :giaddr => 0x0,	
      :chaddr => 0x0
     }
     @options = []
  end

  def initialize(data)
    values = data.unpack('C4NnnN4a6x202Na*')
    @options = []
    @params = {
        :op => values.shift,
        :htype => values.shift,
        :hlen => values.shift,
        :hops => values.shift,

        :xid => values.shift,
        :secs => values.shift,
        :flags => values.shift,
        :ciaddr => values.shift,
        :yiaddr => values.shift,
        :siaddr => values.shift,
        :giaddr => values.shift,
        :chaddr => values.shift,
        :cookie => values.shift
    }
    tmpOptions = values.shift

    # then we load options
    offset =0
    loop do 
       oid,len=tmpOptions.unpack("@"+ offset.to_s + "C2")
       value=tmpOptions.unpack("@" + (offset+2).to_s + "a" + len.to_s)
       value = value[0]
       offset += len+2
       break if oid == 0xff

       if BOOTOPTIONS.key?(oid) 
           option = BOOTOPTIONS[oid].new(oid,len,value)
       else
           option = BootOption.new oid,len,value
       end

       @options << option
    end
  end

  def options
    return @options
  end

  def options=(value)
    @options = value
  end

  def option=(value)
    @options.each do |option|
      if (option.key == value.key)
        option = value
      end
    end
    @options << value
  end

  def remove_option(key)
    opts = []
    @options.each do |opt|
       opts << opt unless opt.key == key
    end
    @options = opts
  end

  def type=(value)
    @options.each do |option|
      if option.is_a?(MessageTypeOption)
        option.type = value
        return
      end
    end
    @options << MesssageTypeOption.new(value)
  end

  def type
    @options.each do |option|
       return option if option.is_a?(MessageTypeOption)
    end
  end

  def pack
    ret = [self.op,self.htype,self.hlen,self.hops,self.xid,self.secs,self.flags,self.ciaddr,self.yiaddr,self.siaddr,self.giaddr,self.chaddr,self.cookie].pack("C4NnnN4a6x202N")
    options.each do |option|
       ret += option.pack
    end
    ret += [0xff].pack('C')
    return ret
  end

  def valid?
    # must have valid type and op
    return false if type.nil? or (op < 1 or op > 2) or (type.type < 1 or type.type > 13) 
    return true
  end

  def params
    @params
  end

  def chaddr_s
    tmp = chaddr.unpack('CCCCCC')
    tmp.map { |c| sprintf("%02x",c) }.join(":")
  end

  def op_s
    if op == 1
      op_s = 'Request'
    else
      op_s = 'Response'
    end
  end

  def to_s
    str = "DHCP Message #{op_s}\n\tFIELDS:\n\t\tTransaction ID = 0x#{xid.to_s(16)}\n\t\tClient IP = #{IPAddr.new(ciaddr, Socket::AF_INET).to_s}\n\t\tYour IP = #{IPAddr.new(yiaddr, Socket::AF_INET).to_s}\n\t\tNext Server IP = #{IPAddr.new(siaddr, Socket::AF_INET).to_s}\n\t\tRelay Agent IP = #{IPAddr.new(giaddr, Socket::AF_INET).to_s}\n\t\tHardware Address = #{chaddr_s}\n\t\tCookie = 0x#{cookie.to_s(16)}\n\n\tOPT:\n";

    @options.each do |option|
        str += "\t\t" + option.to_s + "\n"
    end

    return str
  end

  def method_missing(m, *args, &block)
    if args.size == 0 and @params.key?(m)
      return @params.fetch m.to_sym
    elsif args.size == 1 and m.to_s.end_with?('=') and params.key?(m.to_s.chop.to_sym)
       @params[m.to_s.chop.to_sym] = args[0]
       return
    end
    puts ("method_missing(#{m}, #{args.size})")
    raise NoMethodError.new
  end
end


class DhcpServer
  def initialize(ip, networks)
    @log = Logger.new 'dhcpd'
    #@log.outputters = SyslogOutputter.new('dhcpd', :logopt => 0x1, :facility => 'LOG_DAEMON')
    @log.outputters = Outputter.stderr
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

  def set_options(msg)
    msg.remove_option(55)
    msg.option = SubnetMaskOption.new("255.255.255.255")
    msg.option = RouterOption.new(IPAddr.new(msg.giaddr, Socket::AF_INET).to_s)
    msg.option = DomainNameServerOption.new(["195.10.132.196", "195.10.132.203"])
    msg.option = IPAddressLeaseTimeOption.new(86400)
  end

  def discover2offer(msg)
    offer = msg.clone
    offer.yiaddr = offer.giaddr+1
    offer.op = BootPacket::REPLY
    offer.type = MessageTypeOption::OFFER
    offer.flags = 0x8000
    set_options(offer)
    return offer
  end

  def request2ack(msg)
    ack = msg.clone
    ack.yiaddr = ack.giaddr+1
    ack.op = BootPacket::REPLY
    ack.type = MessageTypeOption::ACK
    set_options(ack)
    return ack
  end

  def run
    @log.info "TDC DHCP started - Binding to #{@ip}:67"

    # socket code
    BasicSocket.do_not_reverse_lookup = true
    @socket  = UDPSocket.new
    @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
    @socket.bind(@ip, 67)

    loop do 
      # yarr..
      read_array = Kernel.select [@socket], nil, nil, 1
      unless read_array.nil? 
         # process message
         begin
            data, addr = @socket.recvfrom(1500)
            imsg = BootPacket.new(data)
         rescue 
            next
         end
         @log.debug "Message received"
         @log.debug imsg.to_s

         next unless imsg.valid?

         case imsg.type.type
            when MessageTypeOption::DISCOVER
              omsg = discover2offer(imsg)
            when MessageTypeOption::REQUEST
              omsg = request2ack(imsg)
            else
              @log.debug "Received #{imsg.type} but cannot handle it" 
              next
         end
         
         @socket.send omsg.pack, 0, addr[3], addr[1]
      end
    end
  end
end

Daemons.run_proc('dhcpd') do 
  app = DhcpServer.new(ip,networks)
  app.run
end

# test some options


