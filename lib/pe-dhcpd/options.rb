# (c) Aki Tuomi 2011 - See license. 
module PeDHCPd
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
  
    def get
      @value.unpack('C*')
    end

    def pack 
      return [@key,@len].pack('CC') + @value if (@value.is_a?(String))
      return ([@key,@len]+@value).pack('CC*') if (@value.is_a?(Array))
      ""
    end
  
    def to_s
      str = "Option #{@key} with #{@len} bytes of data: "
      str += @value.unpack("C*").map { |c| "%02x" % [c] }.join(" ")
    end
  end

  class RelayAgentInformationOption < BootOption
   def build(value)
     @key = 82
     @len = value.size
     if value.is_a?(Array)
       @value = value.pack("C*")
     elsif value.is_a?(String)
       @value = value
     end
   end

   def to_s
     str = "Relay Agent Information = "
     str += @value.bytes.map { |c| "%02x" % [c] }.join
   end
  end
 
  class HostnameOption < BootOption
   def build(value)
     @key = 12
     @len = value.size
     if value.is_a?(Array)
       @value = value.pack("C*")
     elsif value.is_a?(String)
       @value = value
     end
   end

   def to_s
     str = "Hostname = "
     str += @value
   end
  end

  class MaximumDHCPPacketSizeOption < BootOption
     def build(value)
       @key = 57
       @len = 2
       @value = [value].pack('S')
     end

     def to_s
       "Maximum DHCP Packet Size = " + @value.unpack('S').to_s + " seconds"
     end
  end

  class ClassIdentifierOption < BootOption
   def build(value)
     @key = 60
     @len = value.size
     if value.is_a?(Array)
       @value = value.pack("C*")
     elsif value.is_a?(String)
       @value = value
     end
   end

   def to_s
     str = "Class Identifier = "
     str += @value
   end
  end

  class DHCPClientIdentifierOption < BootOption
   def build(value)
     @key = 61
     @len = value.size
     if value.is_a?(Array)
       @value = value.pack("C*")
     elsif value.is_a?(String)
       @value = value
     end
   end

   def to_s
     str = "DHCP Client Identifier = "
     str += @value
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
   
   def to_bits
     # convert directly into prefix
     x = @value.unpack("I")[0]
     x = x - ((x>>1) & 0x55555555)
     x = (x & 0x33333333) + ((x>>2) & 0x33333333)
     x = (x + (x >> 4)) & 0x0F0F0F0F
     x = x + (x >> 8)
     x = x + (x >> 16)
     x & 0x0000003F
   end

   def to_s
     str = "Subnet mask = "
     str += @value.unpack("CCCC").join('.')
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
      str + tmp2.join(", ")
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
     str = "DHCP Server Identifier = "
     str += @value.unpack("CCCC").join('.')
   end
  end
  
  class IPAddressLeaseTimeOption < BootOption
     def build(value)
       @key = 51
       @len = 4
       @value = [value].pack('N')
     end
  
     def to_s
       "IP Address Lease Time = " + @value.unpack('N').to_s + " seconds"
     end
  end
  
  class RenewalTimeValueOption < BootOption
     def build(value)
       @key = 58
       @len = 4
       @value = [value].pack('N')
     end
  
     def to_s
       "Renewal Time Value = " + @value.unpack('N').to_s + " seconds"
     end
  end
  
  class RebindingTimeValueOption < BootOption
     def build(value)
       @key = 59
       @len = 4
       @value = [value].pack('N')
     end
 
     def to_s
       "Rebinding Time Value = " + @value.unpack('N').to_s + " seconds"
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
 
    def type_s  
       case type
        when DISCOVER
          return "Discover"
        when OFFER
          return "Offer"
        when REQUEST
          return "Request"
        when DECLINE
          return "Decline"
        when ACK
          return "ACK"
        when NAK
          return "NAK"
        when RELEASE
          return "Release"
        when INFORM
          return "Inform"
        when FORCERENEW
          return "ForceRenew"
        when LEASEQUERY
          return "LeaseQuery"
        when LEASEUNASSIGNED
          return "LeaseUnassigned"
        when LEASEUNKNOWN
          return "LeaseUnknown"
        when LEASEACTIVE
          return "LeaseActive"
      end
      "Unknown"
    end

    def to_s
      "DHCP Message Type = #{self.type_s}"
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
      str + tmp2.join(", ")
    end
  end
end 
