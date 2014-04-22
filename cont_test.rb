require 'pry'
require_relative './ptrace_wrapper/lib/Ptrace_ext.so'           # Load C extension wrapping ptrace(3)

    PTRACE_COMMANDS = Ptrace::Debugger.commands
    def ptrace_send(pid, cmd, arg=nil )
      begin
        Ptrace::Debugger.send_cmd( PTRACE_COMMANDS[cmd], pid, arg )
      rescue RuntimeError => e
        case e.message
          when 'PTRACE: Operation not permitted'
            raise OperationNotPermittedError.new(e.message)
          when 'PTRACE: No such process'
            raise InvalidProcessError.new(e.message)
          else
            raise
        end
      end
    end

  def wait_for_stop(pid)
    loop do
      Process.waitpid(pid)
      status = $?
      if status.stopsig != 19 && status.stopsig != 5
        puts "unexpected signal #{status}"
        ptrace_send(pid, :cont, status.stopsig)
      else
        return status
      end
    end
  end

pid = fork
if ! pid
  begin
    Ptrace::Debugger.send_cmd(Ptrace::Debugger.commands[:traceme], nil,
                              nil)
    exec("parsec47")
  rescue RuntimeError => e
    case e.message
      when 'PTRACE: Operation not permitted'
        raise OperationNotPermittedError.new(e.message)
      when 'PTRACE: No such process'
        raise InvalidProcessError.new(e.message)
      else
        raise
    end
  end

elsif pid == -1
  raise "wtf nope"
else
  puts wait_for_stop(pid)
  ptrace_send(pid, :cont )
  sleep(1)
  Process.kill("STOP",pid)
  puts wait_for_stop(pid)
  sleep(2)
  ptrace_send(pid, :cont )
  sleep(1)
  Process.kill("STOP",pid)
  puts wait_for_stop(pid)
  sleep 10
  ptrace_send(pid, :cont )
end
