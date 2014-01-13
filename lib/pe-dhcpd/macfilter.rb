module PeDHCPd
 class MacFilter
   def initialize(addr, prefix) 
     # convert into hex
     addr.gsub! /[:.-]/, ""
     @addr = addr.to_i(16)
     @prefix = prefix.to_i
     @mask = (0xffffffffffff >> @prefix) ^ (0xffffffffffff)
     @addr = @addr & @mask
     puts "#{@addr.to_s(16)} #{@mask.to_s(16)}" 
   end

   def match(mac)
     if mac.is_a?(String)
        mac.gsub! /[:.-]/, ""
        mac = mac.to_i(16)
     end
     
     mac = mac & @mask;
     return mac == @addr
   end
 end

 class MacFilterList
   def initialize
      @masks = []
   end

   def <<(x)
     mac,mask = x.split "/"
     mask = "48" if mask.nil?
     @masks << MacFilter.new(mac,mask)
   end

   def each 
     @masks.each do |mask| yield mask end 
   end

   def include?(mac)
      @masks.each do |mask|
        return true if mask.match(mac) 
      end 
      return false
   end
 end
end
