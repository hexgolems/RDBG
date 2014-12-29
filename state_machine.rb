class StateMachine

  def initialize(debugger)
    @debugger = debugger
    @state = Set.new
    @state << :paused
  end

  def sig_num(str)
    return ::Signal.list[str]
  end

  def check_signal(*states, sig)
    return @type == :signal && states.any?{|s| @state.include? s } && @info.stopsig == sig_num(sig)
  end

  def check_trap_bp?
    return check_signal( :running, "TRAP") && @debugger.is_stopped_after_bp?
  end

  def check_trap_step?
    return check_signal( :single_stepping, "TRAP" )
  end

  def check_stop?
    return check_signal( :wait_for_stop, "STOP" )
  end

  def check_exited?
    return @type == :signal && @info.exited?
  end

  def check_action(name)
    return @type == :action && @info.name == name
  end

  def check_action_step?
    return check_action(:step)
  end

  def check_action_continue?
    return check_action(:continue)
  end

  def check_action_pause?
    return check_action(:pause)
  end

  def check_post_bp_step?
    return check_signal( :bp_restoration_step, "TRAP")
  end

  def check_needs_bp_restoration?
    return @state.include? :paused
  end

  def alive?
    return !@state.include?(:dead)
  end

  def paused?
    return @state.include? :paused
  end

  def add_states(*args)
    @state += args
  end

  def remove_states(*args)
    @state -= args
  end

  def do_stop
      add_states(:paused, :bps_removed)
      remove_states(:running, :single_stepping, :wait_for_stop)
      @debugger.remove_all_breakpoints_from_memory()
  end

  def run(type, info)
    @type, @info = type, info

    if check_trap_bp?
      do_stop
      @debugger.decrement_ip!
      return true
    end

    if check_trap_step? || check_stop?
      do_stop
      return true
    end

    if check_exited?
      add_states(:dead)
      return true
    end

    if check_action_step?
      add_states(:single_stepping)
      remove_states(:paused)
      @debugger.send_single_step
      return true
    end

    if check_action_pause?
      add_states(:wait_for_stop)
      @debugger.send_pause
      return true
    end

    if check_action_continue?
      add_states(:bp_restoration_step)
      remove_states(:paused)
      @debugger.send_single_step
      return true
    end

    if check_post_bp_step?
      @debugger.restore_all_breakpoints_to_memory()
      remove_states(:bp_restoration_step, :bps_removed)
      add_states(:running)
      @debugger.send_continue
      return true
    end
    return false
  end

end
