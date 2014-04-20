RBDG
====
This is a simple interface for the Ptrace facilities. It features more comfortable read/write access to the tracees memory etc. Only tested on Ubuntu 64bit.

NOTE: This is currently alpha software, and is released only to publish the
      API of the module. This should not be used in production software, as
      many features are incomplete.

BUILD
-----

First you need to compile the C extension for Ptrace:

	bash# cd ptrace_wrapper/module
	bash# ruby extconf.rb
	bash# make
	bash# cp Ptrace_ext.so ../lib/

Note that the Ruby headers must be installed. On Ubuntu, these are in the
ruby-dev or ruby1.9-dev package.

Example
-------

This example illustrates how to use the RDBG class.

```
require './rdbg.rb'
require 'pp'

d = RDBG.new("sleep 10")

#print infos on all mapped memory ranges
pp d.mappings 

#find the first read only range from the binary
code = d.mappings.find{|m| m[:path].strip =~/sleep/ && m[:permissions]=~/r-/} 

# read the first 100 bytes from the range, should contain the elf header
start = d.read_mem(code[:range].min,100) 
puts start.inspect
start[0..3] = "NOPE"

# overwrites the elf magic bytes in memory (doesn't really matter)
start = d.write_mem(code[:range].min,start) 

#singlestep
d.step
#get register
puts d.get_reg("rip")
#set register
puts d.set_reg("rip", d.get_reg("rip"))
d.step
puts d.get_reg("rip")
d.step
puts d.get_reg("rip")

#continues execution without singlesteping
d.continue 
sleep 1
#pause the execution where ever it currently is
d.pause
#kill the process
d.kill
```
