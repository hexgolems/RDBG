require 'English'
require 'thread'
require_relative './ptrace_wrapper/lib/Ptrace'
require_relative './exceptions.rb'
require_relative './state_machine.rb'

class Action
  attr_accessor :name, :block, :promise
  def initialize(name, promise, &block)
    @name = name
    @promise = promise
    @block = block
  end
end

class PTEventLoop
  attr_accessor :debugger, :loop_thread

  def perform_action(action)
    return if @debugger.statemachine.run(:action, action)
    res = action.block.call(@debugger)
    action.promise << res if action.promise
  end

  def step
    return step_paused if @debugger.statemachine.paused?
    step_running
  end

  def step_paused
    action = @action_queue.pop
    @queue_mutex.synchronize do
      perform_action(action)
    end
  end

  def step_running
    pid = Process.waitpid(@pid)
    status = $CHILD_STATUS
    @queue_mutex.synchronize do
      handle_signal(pid, status)
    end
  end

  def handle_signal(_pid, status)
    return if @debugger.statemachine.run(:signal, status)
    @debugger.target.cont_nonblocking(status.stopsig)
  end

  def run_dbg(cmd)
    @debugger.target = Ptrace::Target.launch(cmd)
    @pid = @debugger.target.pid
  end

  def add_action(action)
    fail ProcessDiedException unless @debugger.statemachine.alive?
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
    @loop_thread = Thread.new do
      run_dbg(cmd)
      step while @debugger.statemachine.alive?
    end
  end
end
