require_relative './ptrace_wrapper/lib/Ptrace'

class RDBG
  def initialize(prog)
    @target = Ptrace::Target.launch(prog)
  end

  def read_mem(addr,len)
    File.open("/proc/#{@target.pid}/mem","rb") do |f|
      f.seek(addr)
      return f.read(len)
    end
  end

  CPU_WORDSIZE_FORMAT = "Q"
  CPU_WORDSIZE = 8

  def write_mem(addr,val)
    range = mappings.find{|map| map[:range].include?(addr)}[:range]
    (0...val.length-(val.length%CPU_WORDSIZE)).step(CPU_WORDSIZE).each do |offset|
      write_word(addr+offset, val[offset...offset+CPU_WORDSIZE])
    end
    incomplete_len = val.length%CPU_WORDSIZE
    if incomplete_len != 0
      last_chunk_end = addr+val.length
      last_chunk_start = addr+val.length-incomplete_len
      rest_data = val[val.length-incomplete_len..-1]
      if last_chunk_start+8 < range.max
        write_in_frame( last_chunk_start, rest_data, (last_chunk_start...last_chunk_start+8) )
      else
        write_in_frame( last_chunk_start, rest_data, (last_chunk_end-8...last_chunk_end) )
      end
    end
  end


  def write_word(addr,val)
    @target.data.poke(addr,val.unpack(CPU_WORDSIZE_FORMAT).first)
  end

  def write_in_frame(addr,val,frame)
    raise "bad writing frame #{frame.inspect} (wrong size)" if frame.max-frame.min+1 != CPU_WORDSIZE
    raise "bad writing frame #{frame.inspect} (invalid addr)" unless frame.include?(addr) && frame.include?(addr+val.length-1)
    templ = read_mem(frame.min, frame.max-frame.min+1)
    offset = addr-frame.min
    templ[offset...offset+val.length] = val
    write_word(frame.min,templ)
  end

  def regs
    @target.regs.read
  end

  def get_reg(reg)
    @target.regs.read[reg]
  end

  def set_reg(reg,val)
    @target.regs[reg]=val
  end

  def mappings()
    mapping_reg = /(?<addr_start>[0-9a-f]+)-(?<addr_end>[0-9a-f]+)\s+(?<permissions>[a-z\-]+)\s+(?<offset>[0-9a-f]+)\s+(?<device>[0-9a-z]+:[0-9a-z]+)\s+(?<inode>[0-9]+)\s*(?<file>.*)/
    maps = File.read("/proc/#{@target.pid}/maps").lines.map{|x| x.match(mapping_reg)}
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

  def continue(blocking = false)
    @target.cont_nonblocking
    wait_stop if blocking
  end

  def wait_stop
    loop do
      s = Process.waitpid(@target.pid)
      status = $?
      if status.exited?
        return false
      elsif status.stopped?
        return true
      end
      puts "unexpected signal #{s} #{$?}"
    end
  end

  def step()
    @target.step
  end

  def pause()
    Process.kill("STOP",@target.pid)
  end

  def kill()
    @target.kill
  end
end
