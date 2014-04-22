require_relative './ptrace_wrapper/lib/Ptrace'
require_relative './ptevloop.rb'

class RDBG
  def initialize(prog)
    @event_loop = PTEventLoop.new(prog)
  end


  def read_mem(addr,len)
    res = Thread.promise
    @event_loop.add_action(Action.new(:read,res){|target,evloop| action_read_mem(target,addr,len)})
    return res.value
  end

  def write_mem(addr,val)
    @event_loop.add_action(Action.new(:write,nil){|target,evloop| action_write_mem(target,addr,val)})
  end

  def action_read_mem(target,addr,len)
    File.open("/proc/#{target.pid}/mem","rb") do |f|
      f.seek(addr)
      return f.read(len)
    end
  end

  def regs
    res = Thread.promise
    @event_loop.add_action(Action.new(:regs,res){|target,evloop| target.regs.read; target.regs})
    return res.value
  end

  def get_reg(reg)
    res = Thread.promise
    @event_loop.add_action(Action.new(:getreg,res){|target,evloop| 
        target.regs.read
        target.regs[reg]
        })
    return res.value
  end

  def set_reg(reg,val)
    @event_loop.add_action(Action.new(:setreg,nil){|target,evloop| target.regs[reg]=val})
  end

  def mappings()
    res = Thread.promise
    @event_loop.add_action(Action.new(:mappings,res){|target,evloop| action_mappings(target)})
    return res.value
  end

  def action_mappings(target)
    mapping_reg = /(?<addr_start>[0-9a-f]+)-(?<addr_end>[0-9a-f]+)\s+(?<permissions>[a-z\-]+)\s+(?<offset>[0-9a-f]+)\s+(?<device>[0-9a-z]+:[0-9a-z]+)\s+(?<inode>[0-9]+)\s*(?<file>.*)/
    maps = File.read("/proc/#{target.pid}/maps").lines.map{|x| x.match(mapping_reg)}
    return maps.map do |m|
      {
        range: (m["addr_start"].to_i(16) ... m["addr_end"].to_i(16)),
        permissions: m["permissions"],
        offset: m["offset"],
        device: m["device"],
        inode: m["inode"],
        path: m["file"]
      }
    end
  end

  def continue()
    @event_loop.add_action(Action.new(:continue,nil){|target,evloop| target.cont_nonblocking; evloop.state = :running })
  end

  def step()
    @event_loop.wait_for_signal("TRAP")
    @event_loop.add_action(Action.new(:step,nil){|target,evloop| target.step; evloop.state = :running })
  end

  def pause()
    @event_loop.wait_for_signal("STOP")
    Process.kill("STOP",@event_loop.target.pid)
  end

  def kill()
    @event_loop.add_action(Action.new(:kill,nil){|target,evloop| target.kill })
  end

  CPU_WORDSIZE_FORMAT = "Q"
  CPU_WORDSIZE = 8

  def action_write_mem(target,addr,val)
    range = action_mappings(target).find{|map| map[:range].include?(addr)}[:range]
    (0...val.length-(val.length%CPU_WORDSIZE)).step(CPU_WORDSIZE).each do |offset|
      write_word(target, addr+offset, val[offset...offset+CPU_WORDSIZE])
    end
    incomplete_len = val.length%CPU_WORDSIZE
    if incomplete_len != 0
      last_chunk_end = addr+val.length
      last_chunk_start = addr+val.length-incomplete_len
      rest_data = val[val.length-incomplete_len..-1]
      if last_chunk_start+8 < range.max
        write_in_frame(target, last_chunk_start, rest_data, (last_chunk_start...last_chunk_start+8) )
      else
        write_in_frame(target, last_chunk_start, rest_data, (last_chunk_end-8...last_chunk_end) )
      end
    end
  end


  def write_word(target,addr,val)
    target.data.poke(addr,val.unpack(CPU_WORDSIZE_FORMAT).first)
  end

  def write_in_frame(target,addr,val,frame)
    raise "bad writing frame #{frame.inspect} (wrong size)" if frame.max-frame.min+1 != CPU_WORDSIZE
    raise "bad writing frame #{frame.inspect} (invalid addr)" unless frame.include?(addr) && frame.include?(addr+val.length-1)
    templ = action_read_mem(target,frame.min, frame.max-frame.min+1)
    offset = addr-frame.min
    templ[offset...offset+val.length] = val
    write_word(target,frame.min,templ)
  end

end
