#!/usr/bin/env ruby
#
# vsaudit.rb - voip auditing framework.
#
# Sanvil Security <security@sanvil.net>
# (c) 2015 - MIT License.
#

['readline', 
 'resolv',
  Dir.pwd + '/core/environment', 
  Dir.pwd + '/core/auditer',
  Dir.pwd + '/core/utility'].each(&method(:require))

# TAB Completion.
LIST = ['set', 'get', 'env', 
        'fcheck', 'scan', 'enum', 'bruteforce', 
        'info', 'report', 'exts', 'session', 
        'live', 'intercept', 'decode',
        'help', 'exit', 'quit'].sort

# Instance the base app objects.
$environ    = Environment.new
$auditer    = Auditer.new
$utility    = Utility.new

# Custom modules instances.
$modules    = []

# Initialize the interactive 
# pseudo-terminal interface.
def run_pts
    begin
        # Pass the completion to proc every-time.
        Readline.completion_append_character = ' '
        Readline.completion_proc = proc { |s| LIST.grep(/^#{Regexp.escape(s)}/) }

        # Read the input command.
        while line = Readline.readline("#{GB}vsaudit > #{RST}", true)
            command = line.split(' ')

            case command.first
                # Environment commands.
                when 'set',         's'     then $environ::set_env(command)
                when 'get',         'g'     then $environ::get_env(command)
                when 'env',         'e'     then $environ::list_env

                # Audit commands.
                when 'fcheck',      'f'     then $auditer::verify_conf_files
                when 'scan',        'sn'    then $auditer::pscan(command)
                when 'enum',        'en'    then $auditer::enum_extensions(command)
                when 'bruteforce',  'bf'    then $auditer::bruteforce(command)

                # Info commands.
                when 'info',        'i'     then $utility::get_info(command)
                when 'report',      'r'     then $auditer::report_scan
                when 'exts',        'ex'    then $auditer::report_extensions
                when 'session',     'se'    then $auditer::session(command)
                when 'live',        'lv'    then $auditer::live(command)
                when 'intercept',   'in'    then $auditer::intercept(command)
                when 'decode',      'dc'    then $auditer::decode(command)

                # Global commands.
                when 'help',        'h'     then $utility::print_help(command)
                when 'exit', 'quit','q'     then 
                    puts "#{GB}+ exiting..#{RST}"
                    raise Exception
                # Try the shell commands.
                else
                    $utility.do_sh_command?(command)
            end
        end
    rescue SystemExit, SignalException
        print "\r\n"
        run_pts
    rescue Exception
        system 'setterm -cursor on'
        exit
    end
end

system 'clear'
system 'setterm -cursor off'

# Load the custom modules.
$utility::load_modules

# Set the base environment options.
$utility::set_base_env

run_pts