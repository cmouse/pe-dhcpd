Pe-DHCP
==========================================================
A simple script to provide link addresses stateless to CPEs.

Installation
------------
To install, use gem install pe-dhcpd, or rake install

Configuration
-------------
Look at contrib/pe-dhcpd.conf and use that.

Running
-------
Look at contrib/pe-dhcpd.init or contrib/upstart.conf, and use 
the one that suits your needs. Modify as needed.

Extending
---------
There are now support for HOOKS in the configuration. If you need to 
load extra gems, run the process with custom Gemfile.

env BUNDLE_GEMFILE="/path/to/gemfile". Yon can get example contents
from contrib/pe-dhcpd.gem

This allows you to extend the system using custom ruby gems and your
own code. 

To write a hook, you need a Class, Proc of function, which you can add
to :discover, :offer, :reply, :acknowledge arrays in HOOKS variable. 

See configuration file for details. 
