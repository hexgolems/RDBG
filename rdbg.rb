require 'set'

require_relative './ptrace_wrapper/lib/Ptrace'
require_relative './ptevloop.rb'
require_relative './exceptions.rb'

class Breakpoint
  attr_accessor :addr, :original_content, :enabled

  def initialize(addr, original_content)
    @addr, @original_content = addr, original_content
    @enabled = true
  end
end

class RDBG

  attr_accessor :statemachine,:target, :breakpoints

  def instruction_pointer
    return "rip"
  end

  def stack_pointer
    return "rsp"
  end

  def base_pointer
    return "rbp"
  end

  def initialize(prog)
    @event_loop = PTEventLoop.new(prog, self)
    @breakpoints = {}
    @statemachine = StateMachine.new(self)
  end

  def read_mem(addr,len)
    res = Thread.promise
    @event_loop.add_action(Action.new(:read,res){|dbg| action_read_mem(dbg.target,addr,len)})
    return res.value
  end

  def write_mem(addr,val)
    @event_loop.add_action(
      Action.new(:write,nil){|dbg| 
        action_write_mem(dbg.target,addr,val)
        update_breakpoint_original_content_by_overwrite(addr,val)
      })
  end


  def regs
    res = Thread.promise
    @event_loop.add_action(Action.new(:regs,res){|dbg| dbg.target.regs.read; dbg.target.regs})
    return res.value
  end

  def get_reg(reg)
    res = Thread.promise
    @event_loop.add_action(Action.new(:getreg,res){|dbg|  action_get_reg( dbg.target, reg ) })
    return res.value
  end


  def set_reg(reg,val)
    @event_loop.add_action(Action.new(:setreg,nil){|dbg| actions_set_reg(target, reg, val)})
  end


  def mappings()
    res = Thread.promise
    @event_loop.add_action(Action.new(:mappings,res){|dbg| action_mappings(dbg.target)})
    return res.value
  end


  def set_bp(addr)
    @event_loop.add_action( Action.new(:set_bp,nil){|dbg| action_set_bp(dbg.target, addr) })
  end


  def disable_bp(bp)
    @event_loop.add_action( Action.new(:disable_bp, nil) { bp.enabled = false } )
  end

  def enable_bp( bp)
    @event_loop.add_action( Action.new(:enable_bp, nil) { bp.enabled = true } )
  end

  def continue()
    @event_loop.add_action( Action.new(:continue, nil) )
  end

  def step()
    @event_loop.add_action( Action.new(:step, nil) )
  end

  def pause()
    @event_loop.add_action( Action.new(:pause, nil) )
  end

  def kill()
    @event_loop.add_action( Action.new( :kill, nil ){|target,evloop| target.kill} )
  end

  def action_set_bp( target,  addr )
    orig_content = action_read_mem( target, addr, 1 )
    @breakpoints[addr]= Breakpoint.new( addr, orig_content )
  end

  def action_read_mem(target,addr,len)
    File.open("/proc/#{target.pid}/mem","rb") do |f|
      f.seek(addr)
      return f.read(len)
    end
  end


  #internal functions that mus only be called from the eventloop thread
  def assert_called_from_loop_thread!
    raise "missuse of api" unless Thread.current == @event_loop.loop_thread
  end
  def action_mappings(target)
    assert_called_from_loop_thread!
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

  def action_get_reg(target, reg)
      assert_called_from_loop_thread!
      target.regs.read
      return target.regs[reg]
  end

  def action_set_reg(target, reg, val)
    assert_called_from_loop_thread!
    target.regs[reg]=val
    target.regs.write
  end

  def send_continue
    assert_called_from_loop_thread!
    target.cont_nonblocking
  end

  def send_single_step
    assert_called_from_loop_thread!
    target.step
  end

  def send_pause
    begin
      Process.kill("STOP",@target.pid)
    rescue Errno::ESRCH
      raise ProcessDiedException
    end
  end

  def restore_all_breakpoints_to_memory
    assert_called_from_loop_thread!
    @breakpoints.each_pair do |addr, bp|
      next unless bp.enabled
      old= bp.original_content
      bp.original_content = action_read_mem(@target, addr, 1)
      action_write_mem(@target, bp.addr, "\xcc")
    end
  end

  def remove_all_breakpoints_from_memory
    assert_called_from_loop_thread!
    @breakpoints.each_pair do |addr, bp|
      action_write_mem(@target, bp.addr, bp.original_content)
    end
  end

  def get_ip
      return action_get_reg( @target, instruction_pointer )
  end

  def decrement_ip!
      action_set_reg( @target, instruction_pointer, get_ip - 1 )
  end


  def is_stopped_after_bp?
      return @breakpoints.include?(get_ip-1)
  end


  CPU_WORDSIZE_FORMAT = "Q"
  CPU_WORDSIZE = 8

  def action_write_mem( target, addr, val )
    assert_called_from_loop_thread!
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

  def update_breakpoint_original_content_by_overwrite(addr,val)
    assert_called_from_loop_thread!
    @breakpoints.each_pair do |bp_addr, bp|
      if (addr...addr+val.length).include? bp_addr
        new_content = val[bp_addr-addr]
        bp.original_content = new_content
      end
    end
  end

  def write_word(target,addr,val)
    assert_called_from_loop_thread!
    target.data.poke(addr,val.unpack(CPU_WORDSIZE_FORMAT).first)
  end

  def write_in_frame(target,addr,val,frame)
    assert_called_from_loop_thread!
    raise "bad writing frame #{frame.inspect} (wrong size)" if frame.max-frame.min+1 != CPU_WORDSIZE
    raise "bad writing frame #{frame.inspect} (invalid addr)" unless frame.include?(addr) && frame.include?(addr+val.length-1)
    templ = action_read_mem(target,frame.min, frame.max-frame.min+1)
    offset = addr-frame.min
    templ[offset...offset+val.length] = val.force_encoding("binary")
    write_word(target,frame.min,templ)
  end

end
