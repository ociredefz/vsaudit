#!/usr/bin/env ruby
#
# utility.rb - voip auditing framework.
#
# Sanvil Security <security@sanvil.net>
# (c) 2015 - MIT License.
#

class Utility
    public

    # Load the custom modules.
    def load_modules
        puts "  ---------------------------------------------------------------"
        puts "  #{GB}vsaudit v#{VERSION} #{RST}- voip/sip auditing framework             "
        puts "  ---------------------------------------------------------------"

        i = 0
        Dir.glob(Dir.pwd + '/modules/*.rb') { |rb_file| i += 1
            print "  #{GB}Loading module:#{RST} ", rb_file.split('/').last
            require rb_file

            instance_name = rb_file.split('/').last.sub(/.rb/, '').capitalize << 'Module'
            $modules << Object.const_get(instance_name)

            module_name = Object.const_get(instance_name).class_variable_get(:@@module).first[:name]
            puts "\t#{GB}:#{RST} %s" % [module_name]
        }

        puts "  #{GB}Loaded: #{RST}#{i}\n\n"
    end

    # Set the base environment options.
    def set_base_env
        $environ::set_env([nil, 'PORT',      '5060'], false)
        $environ::set_env([nil, 'TIMEOUT',   '1'],    false)
        $environ::set_env([nil, 'TRANSPORT', 'udp'],  false)
        $environ::set_env([nil, 'IFACE',     'any'],  false)
        $environ::set_env([nil, 'THREADS',   '50'],   false)
        $environ::set_env([nil, 'DUMPHEX',   'off'],  false)
        $environ::set_env([nil, 'DUMPCLEAN', 'on'],   false)
    end

    # Get the informations about module 
    # or address in report list.
    def get_info(command)
        command.shift

        unless command.empty?
            name = command.take(1).first

            # Check for the address in report list.
            found = _get_device_info(name)

            # Loop through the modules and 
            # execute the context method.
            $modules.each { |m|
                if m.to_s.gsub(/Module/, '').downcase == name
                    puts "\n Module '#{GB}%s#{RST}' found:\n\n" \
                        " #{GB}+ Name:#{RST}\t %s v.%s\n" \
                        " #{GB}+ Author:#{RST}\t %s <%s>\n\n" \
                        " #{GB}+ Description:#{RST}\t %s\n\n" % [ 
                        name,
                        m.class_variable_get(:@@module).first[:name],
                        m.class_variable_get(:@@module).first[:version],
                        m.class_variable_get(:@@module).first[:author],
                        m.class_variable_get(:@@module).first[:email],
                        m.class_variable_get(:@@module).first[:description] 
                    ]

                    found += 1
                end
            }

            if found == 0
                return puts "#{RB}- note:#{RST} no information found about modules or address"
            end
        else 
            return puts "#{RB}- error:#{RST} use instead #{GB}info [module|addr]#{RST}"
        end
    end

    # Check if shell command exists, this function
    # starts when a vsaudit command was not found.
    def do_sh_command?(command)
        command.each { |c| 
            c.gsub!(/^(ls)/, 'ls --color')
        }

        system(command.join(' '))
    end

    # Validate an IPV4 address.
    def valid_address?(addr)
        addr.each { |x| 
            if x.include?('/')
                # Match the netblock (ex. ip/8 ip/16 ip/24 ...)
                if x =~ /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]{1,3})$/
                    return true
                else
                    puts "#{RB}- error:#{RST} you have entered an invalid address (ex. 10.10.1.0[/24])"
                    return false
                end
            else
                # Check for a valid address.
                begin
                    Resolv.getaddress(x)
                    return true
                rescue Resolv::DNS::Config::NXDomain, Resolv::ResolvError
                    puts "#{RB}- error:#{RST} you have entered an invalid address (ex. 10.10.1.0[/24])"
                    return false
                end
            end
        }

        return false
    end

    # Validate a single IPV4 address.
    def valid_single_address?(addr)
        # Check for a valid address.
        begin
            Resolv.getaddress(addr)
            return true
        rescue Resolv::DNS::Config::NXDomain, Resolv::ResolvError
            puts "#{RB}- error:#{RST} you have entered an invalid address (ex. 10.10.1.0)"
            return false
        end

        return false
    end

    # Validate the ports range.
    def valid_ports_range?(range)
        if range.to_s.include?('-')
            if range.first.to_s =~ /^([0-9]{1,5})(\-)([0-9]{1,5})$/
                return true
            else
                puts "#{RB}- error:#{RST} you have entered an invalid ports range (ex. 0-65535)"
                return false
            end
        else
            if range.first.to_s =~ /^([0-9]{1,5})$/
                return true
            else
                puts "#{RB}- error:#{RST} you have entered an invalid ports range (ex. 0-65535)"
                return false
            end
        end
    end

    # Validate the scanner timeout value.
    # Possibles values are floats or integers.
    def valid_timeout?(seconds)
        begin
            return true if Float(seconds.first) != nil
            raise Exception
        rescue Exception
            puts "#{RB}- error:#{RST} you have entered an invalid timeout 1|0.5  (seconds/millisecs)"
            return false
        end
    end

    # Validate the scanner thread limit value.
    # Possibles values are integers.
    def valid_threads_limit?(seconds)
        begin
            return true if Integer(seconds.first) != nil
            raise Exception
        rescue Exception
            puts "#{RB}- error:#{RST} you have entered an invalid threads limit 1|200"
            return false
        end
    end

    # Validate the transport value.
    # Possibles values are udp or tcp.
    def valid_transport?(transport)
        if transport.first.to_s.downcase =~ /^(udp|tcp)$/
            return true
        else
            puts "#{RB}- error:#{RST} you have entered an invalid transport udp|tcp"
            return false
        end
    end

    # Validate the interface name.
    def valid_interface?(iface)
        if iface.first.to_s =~ /^([a-z]{1,8}[0-9]{0,4})$/
            return true
        else
            puts "#{RB}- error:#{RST} you have entered an invalid interface eth0|wlan1|other2"
            return false
        end
    end

    # Validate on off values.
    # Possibles values are on or off.
    def valid_onoff?(transport)
        if transport.first.to_s.downcase =~ /^(on|off)$/
            return true
        else
            puts "#{RB}- error:#{RST} you have entered an invalid value on|off"
            return false
        end
    end

    # Display the help message.
    def print_help(command = [])
        disp = false
        command.shift

        unless command.empty?
            command = command.last.to_s.downcase
        end

        if command.empty? || command.include?('description')
            puts "\n    #{GB}+ DESCRIPTION:#{RST}"
            puts "  \n"
            puts "        This is a opensource tool to perform attacks to general voip services"
            puts "        It allows to scans the whole network or single host to do the gathering"
            puts "        phase, then it is able to search for most known vulnerabilities on the"
            puts "        founds alive hosts and try to exploit them."
            puts "  \n"
            disp = true
        end

        if command.empty? || command.include?('environment')
            puts "\n    #{GB}+ ENVIRONMENT COMMANDS:#{RST}"
            puts "  \n"
            puts "        #{RB}Command\t\tArgs\t\t\tDescription#{RST}"
            puts "        s|set\t\t[key] [value]\t\tSet an environment variable"
            puts "        g|get\t\t[key]\t\t\tGet an environment variable value/s"
            puts "        e|env\t\t-\t\t\tDisplay all environment variables"
            puts "  \n"
            disp = true
        end

        if command.empty? || command.include?('environment')
            puts "\n    #{GB}+ ENVIRONMENT VARIABLES:#{RST}"
            puts "  \n"
            puts "  #{RB}Option\t\tValue\t\t\tDescription#{RST}"
            puts "        PORT\t\t[*r|5060]\t\tSet port range (default: 5060)"
            puts "        TIMEOUT\t\t[1|0.5]\t\t\tSet scanner timeout connect()/recv() (default: 1 seconds)"
            puts "        THREADS\t\t[1|200]\t\t\tSet scanner threads limit (default: 50 concurrency)"
            puts "        TRANSPORT\t[udp|tcp]\t\tSet transport for enumeration/bruteforce (default: udp)"
            puts "        IFACE\t\t[eth0|wlan1]\t\tIndicate which interface use to capture network traffic (default: eth0)"
            puts "        DUMPHEX\t\t[on|off]\t\tDump network traffic in hexadecimal (default: off)"
            puts "        DUMPCLEAN\t[on|off]\t\tClear network traffic skipping unicode frame bytes (default: on)"
            puts "  \n"
            puts "        * #{GB}r: range\t#{RST}ex. '0-65535'"
            puts "  \n"
            disp = true
        end

        if command.empty? || command.include?('audit')
            puts "\n    #{GB}+ AUDIT COMMANDS:#{RST}"
            puts "  \n"
            puts "        #{RB}Command\t\tArgs\t\t\tDescription#{RST}"
            puts "        f|fcheck\t-\t\t\tCheck for common configurations mistakes"
            puts "        sn|scan\t\t[addr[/24]]\t\tStart information gathering scanner"
            puts "        en|enum\t\t[*r|*e] [addr]\t\tEnumerate/Test sip extensions (accounts)"
            puts "        bf|bruteforce\t[*r|*e] [*p] [addr]\tTry to bruteforce sip extension(s)"
            puts "  \n"
            puts "        * #{GB}r: range\t#{RST}ex. 0500-6000"
            puts "        * #{GB}e: ext-file\t#{RST}ex. 'ext-list'"
            puts "        * #{GB}p: psw-file\t#{RST}ex. 'psw-list'"
            puts "  \n"
            disp = true
        end

        if command.empty? || command.include?('filters')
            puts "\n    #{GB}+ PCAP BASE FILTERS:#{RST}"
            puts "  \n"
            puts "        #{RB}Filter\t\t\t\t\tDescription#{RST}"
            puts "        udp dst port 5060\t\t\tIntercept destination udp traffic to destination port 5060"
            puts "        tcp port 5060\t\t\t\tIntercept source and destination tcp traffic from source port 5060"
            puts "        ip host 192.168.1.100\t\t\tIntercept source and destination both udp/tcp traffic"
            puts "        password\t\t\t\tIntercept the sip md5 challenge response hash (WWW-Authenticate)"
            puts "  \n"
            disp = true
        end

        if command.empty? || command.include?('information')
            puts "\n    #{GB}+ INFO COMMANDS:#{RST}"
            puts "  \n"
            puts "        #{RB}Command\t\tArgs\t\t\tDescription#{RST}"
            puts "        i|info\t\t[module|addr]\t\tReturn informations about module or address in report list"
            puts "        r|report\t-\t\t\tShow scanner report with grouped trasports data"
            puts "        ex|exts\t\t-\t\t\tShow extensions enumeration report"
            puts "        se|session\t[list|session_id]\tShow extensions enumeration report"
            puts "        lv|live\t\t[addr]\t\t\tGet all or filtered live network traffic data"
            puts "        in|intercept\t[pcap-filter]\t\tFilter network traffic using pcap filters (live extended)"
            puts "        dc|decode\t[raw-file]\t\tDecode on-the-fly raw data-file stream (listen the voice-call)"
            puts "  \n"
            puts "        #{GB}* #{RST}decode: this function is currently in development - do not use it."
            puts "        #{GB}* #{RST}intercept: append option '#{GB}detach#{RST}' to sessionize action"
            puts "        #{GB}* #{RST}intercept: append option '#{GB}record#{RST}' to save stream to file"
            puts "  \n"
            disp = true
        end

        if command.empty? || command.include?('global')
            puts "\n    #{GB}+ GLOBAL COMMANDS:#{RST}"
            puts "  \n"
            puts "        #{RB}Command\t\tArgs\t\t\tDescription#{RST}"
            puts "        q|quit|exit\t-\t\t\tExit"
            puts "        h|help\t\t[what]\t\t\tDisplay this or filtered message"
            puts "\t\t\t\t\t\tdescription | environment | audit | filters | informations | global\n"
            disp = true
        end

        if disp === false
            puts "#{RB}- error:#{RST} use instead #{GB}help#{RST} or #{GB}h [what]#{RST}"
        end
    end

    private

    # Get the extensions list that is 
    # related to name if exists.
    def _get_device_info(name)
        found = 0

        begin
            name = Resolv.getaddress(name)
        rescue Exception
            return 0
        end

        $auditer::report_list.each { |r|
            if r.first[:service_address] == name then found += 1
                puts "\n Address '#{GB}%s#{RST}' found:\n\n" \
                    " #{GB}+ Device:#{RST}\t %s\n" \
                    " #{GB}+ Port:#{RST}\t %s\n\n" \
                    " #{GB}+ Motd:#{RST}\t %s\n" % [
                    r.first[:service_address], 
                    r.first[:service_address], 
                    r.first[:service_port], 
                    r.first[:service_name]
                ]

                puts " #{GB}+ Allows:#{RST}\t %s" % [r.first[:service_methods]] if !r.first[:service_methods].empty?
                puts "\n #{GB}+ Extensions:#{RST}" unless name.nil?

                $auditer::report_extensions(name)
            end
        }

        return found
    end
end
