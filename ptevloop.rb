require_relative './promise.rb'
require_relative './ptrace_wrapper/lib/Ptrace'
require_relative './exceptions.rb'
require_relative './state_machine.rb'

class Action
  attr_accessor :name,:block,:promise
  def initialize(name,promise,&block)
    @name,@promise,@block = name,promise,block
  end
end

class PTEventLoop

  attr_accessor :debugger

  def perform_action(action)
    if not @debugger.statemachine.run(:action, action)
      puts "got nondefault action"
      res = action.block.call(@debugger)
      action.promise << res if action.promise
    end
  end

  def step
    if @debugger.statemachine.paused?
      step_paused
    else
      step_running
    end
  end

  def step_paused
    action = @action_queue.pop
    puts "perform action #{action.inspect}"
    @queue_mutex.synchronize do
      perform_action(action)
    end
  end

  def step_running
    pid = Process.waitpid(@pid)
    status = $?
    puts "handle signal #{status}"
    puts "at #{@debugger.get_ip.to_s(16)}"
    @queue_mutex.synchronize do
      handle_signal(pid,status)
    end
  end

  def handle_signal( pid, status )
    if not @debugger.statemachine.run(:signal, status)
      puts "unexpected: #{pid} #{status}, continueing"
      @debugger.target.cont_nonblocking( status.stopsig )
    end
  end

  def run_dbg( cmd )
    @debugger.target = Ptrace::Target.launch( cmd )
    @pid = @debugger.target.pid
  end

  def add_action(action)
    raise ProcessDiedException unless @debugger.statemachine.alive?
    @queue_mutex.synchronize do
      if action.name == :pause && !@debugger.statemachine.paused?
        @debugger.statemachine.add_states(:wait_for_stop)
        @debugger.send_pause
      else
        @action_queue << action
      end
    end
  end

  def initialize(cmd, debugger)
    @action_queue = Queue.new
    @debugger = debugger
    @queue_mutex = Mutex.new
    Thread.new do
      run_dbg(cmd)
      while @debugger.statemachine.alive?
          puts "="*80
          puts @debugger.breakpoints.inspect
          #puts @debugger.statemachine.state.inspect
          step
      end
    end
  end

end
