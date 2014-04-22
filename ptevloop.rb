require_relative './promise.rb'
require_relative './ptrace_wrapper/lib/Ptrace'
class Action
  attr_accessor :name,:block,:promise
  def initialize(name,promise,&block)
    @name,@promise,@block = name,promise,block
  end
end

class PTEventLoop

  attr_accessor :state, :target

  def step
#puts "step #{@state.inspect}"
    if @state == :stopped
      step_stopped
    elsif @state == :running
      step_running
    else
      raise "invalid state"
    end
  end

  def perform_action(action)
    res = action.block.call(@target,self)
    action.promise << res if action.promise
  end

  def step_stopped
    action = @action_queue.pop
    perform_action(action)
  end

  def step_running
    pid = Process.waitpid(@pid)
    status = $?
    handle_event(pid,status)
  end

  def expected_event(pid, status)
    @awaited_signals_mutex.synchronize do
    puts "awaiting #{@awaited_signals.inspect}"
      if @awaited_signals.include?(status.stopsig)
        @awaited_signals -= [status.stopsig]
        puts "awaiting now #{@awaited_signals.inspect}"
        return true
      end
      return false
    end
  end

  def handle_event(pid,status)
    if !expected_event(pid,status)
      puts "unexpected: #{pid} #{status}, continueing"
      @target.cont_nonblocking(status.stopsig)
    else
      @state = :stopped
    end
  end

  def run_dbg(cmd)
    @target = Ptrace::Target.launch(cmd)
    @pid = @target.pid
    @state = :stopped
    @awaited_signals = []
  end

  def wait_for_signal(*signals)
    @awaited_signals_mutex.synchronize do
      @awaited_signals += signals.map{|str| ::Signal.list[str]}
    end
  end

  def add_action(action)
    @action_queue << action
  end

  def initialize(cmd)
    @awaited_signals_mutex = Mutex.new
    @action_queue = Queue.new
    Thread.new do
      run_dbg(cmd)
      loop do
        step
      end
    end
  end
end
