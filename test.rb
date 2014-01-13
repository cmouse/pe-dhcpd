#!/usr/bin/ruby

require 'rubygems'
require 'bundler/setup'
require 'socket'
require 'net-dhcp'
require 'ipaddr'
require 'pe-dhcpd'

include PeDHCPd

# send to 1.2.3.4 / 67

s = UDPSocket.new

p = DHCP::Discover.new
p.giaddr = IPAddr.new('127.0.0.1').to_i

puts p

s.send p.pack, 0, '127.0.0.1', 67

d, addr = s.recvfrom(1500)

t = DHCP::Message.from_udp_payload(d)
puts t

# build packet to send
p = DHCP::Request.new

p.giaddr = t.giaddr
p.ciaddr = t.yiaddr
p.yiaddr = t.yiaddr
p.chaddr = t.chaddr

p.options = [
  DHCP::MessageTypeOption.new(:payload => [3])
]
p.xid = t.xid

puts p

s.send p.pack, 0, '127.0.0.1', 67

d, addr = s.recvfrom(1500)
t = DHCP::Message.from_udp_payload(d)
puts t
