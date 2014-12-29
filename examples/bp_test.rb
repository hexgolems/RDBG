require '../rdbg.rb'
require 'pry'

cmd = "/usr/games/parsec47"
#cmd = "/bin/ls"

addr = 0x406FCC
Thread.abort_on_exception = true
d = RDBG.new(cmd)
puts "started"
d.set_bp(addr)
puts "added bp"
d.continue()
sleep(2)
puts "continue from bp"
d.continue()
sleep(2)
