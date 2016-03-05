require_relative '../rdbg.rb'

cmd = "/usr/games/parsec47"

# step first ten instructions, printing bytes at EIP and ESP

def get_writable_mappings(d)
  d.mappings.select{|m| m[:permissions].include?("w") && !m[:permissions].include?("s")}
end

def run_and_wait(d)
  d.continue
  puts "Enter the current value of lives"
  target = gets.strip.to_i
  d.pause
  puts "fnord1"
  return target
end

d = RDBG.new(cmd)
target = run_and_wait(d)
offsets =[]
puts "blubl"
get_writable_mappings(d).each do |m|
  puts "reading mapping #{m}"
  str = d.read_mem(m[:range].min, m[:range].max-m[:range].min+1)
  puts str[0..1000].inspect
  str.each_byte.with_index do |byte,offset|
    offsets << m[:range].min+offset if byte == target
  end
  puts "found #{offsets.length} addresses"
end

loop do
  next_target = run_and_wait(d)
  puts "foo"
  next_offsets =[]
  puts "fnord2"
  offsets.each do |o|
    next_offsets << o if d.read_mem(o,1) == next_target.chr
  end
  offsets = next_offsets
  if offsets.length == 1
    puts "found offset #{offsets.first}"
    break
  end
  puts "found #{offsets.length} addresses"
  puts offsets if offsets.length < 10
end

d.write_mem(offsets.first,[9999].pack("L"))
d.continue

loop do
  sleep 1
end
