Gem::Specification.new do |s|
   s.name = 'pe-dhcpd'
   s.version = '1.2'
   s.licenses = 'MIT'
   s.platform = Gem::Platform::RUBY
   s.summary = 'A simple, extensible dhcp server for telco use'
   s.description = 'A simple DHCP server primarily for telco use. It is used to provide IPv4 addresses using stateless algorithm.'
   s.authors = ['Aki Tuomi', 'Saku Ytti']
   s.email = 'cmouse@cmouse.fi'
   s.files = `git ls-files`.split /\n/
   s.executables = %w( pe-dhcpd )
   s.homepage = 'https://github.com/cmouse/pe-dhcpd'
   s.add_runtime_dependency 'log4r'
   s.add_runtime_dependency 'daemons'
   s.add_runtime_dependency 'net-dhcp'
   s.add_development_dependency 'rake'
   s.add_development_dependency 'yard'
end
