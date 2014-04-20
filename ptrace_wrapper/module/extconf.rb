#!/usr/bin/env ruby

require 'mkmf'

if RUBY_VERSION =~ /1.8/ then
        $CPPFLAGS += " -DRUBY_18"
elsif RUBY_VERSION =~ /1.9/ then
        $CPPFLAGS += " -DRUBY_19"
elsif RUBY_VERSION =~ /2.0/ then
        $CPPFLAGS += " -DRUBY_20"
end

create_makefile('Ptrace_ext')
