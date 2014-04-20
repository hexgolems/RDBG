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
