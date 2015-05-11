#!/usr/bin/env ruby
#
# environment.rb - voip auditing framework.
# Copyright (c) 2015 Sanvil Security.
#

require Dir.pwd << '/core/utilities'

VERSION			= '2015.2'
ENV_PREFIX		= 'VS__'

# BASH-LIKE colors.
RST	= "\e[0m"
WL	= "\e[37m"
WB	= "\e[1;37m"
RL	= "\e[31m"
RB	= "\e[1;31m"
GL	= "\e[32m"
GB	= "\e[1;32m"
YL	= "\e[33m"
YB	= "\e[1;33m"
BL	= "\e[34m"
BB	= "\e[1;34m"
PL	= "\e[35m"
PB	= "\e[1;35m"
CL	= "\e[36m"
CB	= "\e[1;36m"

class Environment < Utilities
	protected

	# Availables environment options list,
	# with the mapped callback functions.
	@@env_options = [
		'PORT'		=> 'valid_ports_range?',
		'TIMEOUT'	=> 'valid_timeout?',
		'TRANSPORT'	=> 'valid_transport?',
		'IFACE'		=> 'valid_interface?',
		'THREADS'	=> 'valid_threads_limit?',
		'DUMPHEX'	=> 'valid_onoff?',
		'DUMPCLEAN'	=> 'valid_onoff?'
	]

	public

	# Gets list of environment variables.
	def list_env
		if ENV.keys.grep(/#{ENV_PREFIX}/).length === 0
			return puts "- note: environment table is empty"
		end

		ENV.sort.select { |name, value| 
			if name.include?(ENV_PREFIX)
				puts "#{GB}-> %s:#{RST} \t%s" % [name.sub(ENV_PREFIX, '').upcase, value]
			end
		}
	end
	
	# Sets a key value.
	def set_env(command, prt = nil)
		command.shift

		unless command.empty?
			arguments = command.take(2)
			option = arguments.first.upcase
			value  = arguments.last

			if @@env_options.first.include?(option)
				if not @@env_options.first[option].nil?
					if self::send(@@env_options.first[option], [value]) === true
						puts "#{GB}+ setting key:#{RST} %s value: %s" % [option, value] if prt.nil?
						ENV.store(ENV_PREFIX + option, value)
					end
				else
					puts "#{GB}+ setting key:#{RST} %s value: %s" % [option, value] if prt.nil?
					ENV.store(ENV_PREFIX + option, value)
				end
			else
				puts "#{RB}- error:#{RST} exec help to show availables options" if prt.nil?
			end
		else
			puts "#{RB}- error:#{RST} use instead #{GB}set [key] [value]#{RST}" if prt.nil?
		end
	end

	# Gets a key value.
	def get_env(command, getv = nil)
		command.shift

		unless command.empty?
			arguments = command.take(1)
			option = arguments.first.upcase

			if ENV.key?(ENV_PREFIX + option)
				value = ENV.fetch(ENV_PREFIX + option)
				return value if not getv.nil?

				puts "#{GB}-> %s#{RST}: %s" % [option, value]
			else
				puts "#{RB}- note:#{RST} key-option not found" if getv.nil?
			end
		else
			puts "#{RB}- error:#{RST} use instead #{GB}get [key]#{RST}" if getv.nil?
		end
	end
end
