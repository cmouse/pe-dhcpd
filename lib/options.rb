# (c) Aki Tuomi 2011 - See license. 
module PeDHCP
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
      str += @value.unpack("C*").map { |c| sprintf("%02x", c) }.join(" ")
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
       @value = [value].pack('N')
     end
  
     def to_s
       return "IP Address Lease Time = " + @value.unpack('N').to_s + " seconds"
     end
  end
  
  class RenewalTimeValueOption < BootOption
     def build(value)
       @key = 58
       @len = 4
       @value = [value].pack('N')
     end
  
     def to_s
       return "Renewal Time Value = " + @value.unpack('N').to_s + " seconds"
     end
  end
  
  class RebindingTimeValueOption < BootOption
     def build(value)
       @key = 59
       @len = 4
       @value = [value].pack('N').unpack('CCCC')
     end
  
     def to_s
       return "Rebinding Time Value = " + @value.unpack('N').to_s + " seconds"
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
  
  class NetworkTimeProtocolServersOption < BootOption
    def build(value)
      @key = 42
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
      return "Network Time Protocol Servers = invalid value (data not congruent to 4)" unless (tmp1.size % 4) == 0
      str = "Network Time Protocol Servers = "
      tmp2 = []
      while tmp1.size > 0
       tmp2 << tmp1.shift(4).join('.')
      end
      return tmp2.join("\n")
    end
  end
end 
