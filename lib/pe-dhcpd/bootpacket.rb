require 'lib/options'
require 'ipaddr'

module PeDHCPd
  class BootPacket
    attr_accessor :options

    REQUEST = 1
    REPLY = 2
  
    BOOTOPTIONS = {
          1 => SubnetMaskOption,
          3 => RouterOption,
          6 => DomainNameServerOption,
          12 => HostnameOption,
          42 => NetworkTimeProtocolServersOption,
          50 => RequestedIPAddressOption,
          51 => IPAddressLeaseTimeOption, 
          53 => MessageTypeOption,
          54 => DHCPServerIdentifierOption,
          55 => ParameterRequestListOption,
          57 => MaximumDHCPPacketSizeOption,
          58 => RenewalTimeValueOption,
          59 => RebindingTimeValueOption,
          60 => ClassIdentifierOption,
          61 => DHCPClientIdentifierOption,
          82 => RelayAgentInformationOption
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
         break if oid==0xff
         value=tmpOptions.unpack("@" + (offset+2).to_s + "a" + len.to_s)
         value = value[0]
         offset += len+2
  
         if BOOTOPTIONS.key?(oid) 
             option = BOOTOPTIONS[oid].new(oid,len,value)
         else
             option = PeDHCPd::BootOption.new oid,len,value
         end
  
         @options << option
      end
    end
  
    def get_option(num)
      @options.each do |option|
        return option if (option.key == num)
      end 
      return nil
    end

    def set_option(value)
      @options.each do |option|
        if (option.key == value.key)
          $log.debug "Replacing #{option.class}"
          option = value
          return
        end
      end
      $log.debug "Adding #{value.class}"
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
        if option.is_a?(PeDHCPd::MessageTypeOption)
          option.type = value
          return
        end
      end
      set_option(PeDHCPd::MessageTypeOption.new(value))
    end
  
    def type
      @options.each do |option|
         return option if option.is_a?(PeDHCPd::MessageTypeOption)
      end
      nil
    end
  
    def pack
      ret = [self.op,self.htype,self.hlen,self.hops,self.xid,self.secs,self.flags,self.ciaddr,self.yiaddr,self.siaddr,self.giaddr,self.chaddr,self.cookie].pack("C4NnnN4a6x202N")
      options.each do |option|
         ret += option.pack
      end
      ret += [0xff].pack('C')
  
      if ret.size < 300
         pad = 300-ret.size
         pad.times { ret += [0].pack('C') }
      end
      return ret
    end
  
    def valid?
      # must have valid type and op
      return false unless params[:cookie] == 0x63825363
      return false if type.nil? or type.is_a?(MessageTypeOption)==false or (op < 1 or op > 2) or (type.type < 1 or type.type > 13) 
      true
    end
  
    def params
      @params
    end

    def ciaddr_s
      IPAddr.new(ciaddr, Socket::AF_INET)
    end

    def yiaddr_s
      IPAddr.new(yiaddr, Socket::AF_INET)
    end
  
    def giaddr_s
      IPAddr.new(giaddr, Socket::AF_INET)
    end  

    def chaddr_s
      "%02x%02x.%02x%02x.%02x%02x" % chaddr.unpack('CCCCCC')
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
  
      str
    end
  
    def method_missing(m, *args, &block)
      if args.size == 0 and @params.key?(m)
        return @params.fetch m.to_sym
      elsif args.size == 1 and m.to_s.end_with?('=') and params.key?(m.to_s.chop.to_sym)
         @params[m.to_s.chop.to_sym] = args[0]
         return
      end
      $log.debug("method_missing(#{m}, #{args.size})")
      raise NoMethodError.new
    end
  end
end 
