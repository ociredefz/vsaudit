#!/usr/bin/env ruby
#
# auditer.rb - voip auditing framework.
#
# Sanvil Security <security@sanvil.net>
# (c) 2015 - MIT License.
#

require 'pcaprub'
require 'digest'
require 'ipaddr'
require 'date'

BASH_PATH           = '/bin/bash'
RAW_PATH            =  Dir.pwd + '/raw/'
LISTS_PATH          =  Dir.pwd + '/list/'

PCAP_RAW_FILE       = 'data.raw'
PCAP_WAV_FILE       = 'data.wav'
PCAP_PACKET_SIZE    =  65535

class Auditer < Utilities
    protected

    # Network interface.
    @@interface     = 'any'

    # Default transport.
    @@transport     = 'udp'

    # Default ports range.
    @@start_port    = 5060
    @@end_port      = 5060

    # Timeout value.
    @@timeout       = 1

    # Threads limit value.
    @@threads_limit = 50

    # Threads limit value.
    @@dump_hex      = 'on'

    # Threads limit value.
    @@dump_clean    = 'off'

    # Recursive mode.
    @@recursive     = false

    # Capture descriptor.
    @@capture       = []

    # Threads list.
    @@threads       = []

    # Silent mode.
    @@silent        = []

    public

    # Report list.
    @@report_list   = []

    # Extensions list.
    @@extensions_list   = []

    # Report list reference.
    def report_list
        @@report_list
    end

    # Perform the auditing on configuration
    # files of various voip services.
    def verify_conf_files
        puts "\n  #{GB}Checking for flaws or mistakes in the configuration files..#{RST}\n"

        # Loop through the modules and 
        # execute the context method.
        $modules.each { |m| 
            services_files = m.class_variable_get(:@@services_files).first

            services_files.each { |f| found = 0
                file = f.first

                print "\n",
                    "  Checking filename: \t%s\n" % [file], 
                    "  regexp to matchs:\t%s\n\n" % [f.last]

                begin
                    if File.open(file).lines.any? { |line|
                        if line =~ f.last
                            found += 1
                            puts "\t#{GB}+ Line #{$.}#{RST}: un-safe parameter found '#{RB}#{line.strip}#{RST}'"
                        end
                    }
                    end
                rescue Exception
                    puts "\t#{RB}- error:#{RST}file doesn't exists#{RST}\n\n"
                    found = false
                ensure
                    if found == 0
                        puts "\t#{GB}+ file seems to be okay#{RST}\n\n"
                    end
                end
            }
        }
    end

    # Dispatch the scan type.
    def pscan(command)
        command.shift

        unless command.empty? || command.length < 1
            arguments = command.take(2)
            address   = arguments.first.to_s

            # Check and parse the netblock range
            # format if exists.
            if address.include?('/')
                puts "#{GB}+ netblock in-addr:#{RST} type an ip address or press enter to scan ip/s recursively"
                print "#{GB}> #{RST}"
                
                data = gets.chomp
                
                if data.length > 2
                    if valid_address?([data]) === true
                        address = data
                    else
                        return false
                    end
                else
                    @@recursive = true
                end
            else
                return false unless valid_single_address?(address)

                # Force address to be in ipv4 format.
                if not Resolv.getaddress(address).include?('::1')
                    address = Resolv.getaddress(address)
                end
            end

            # Get and set the environment global variables.
            _set_ports
            _set_timeout
            _set_transport
            _set_threads_limit

            # Dispatch the transport.
            case @@transport
                when 'tcp' then init_scan(address)
                when 'udp' then init_scan(address)
            end 
        else
            return puts "#{RB}- error:#{RST} use instead #{GB}scan [addr]#{RST}"
        end
    end

    # Initialize TCP/UDP port scanner.
    def init_scan(address)
        start_port  = @@start_port
        end_port    = @@end_port

        print "\n",
            "  #{GB}starting scan on address:#{RST} \t%s\n" % [address], 
            "  #{GB}using ports-range:#{RST}\t\t%s-%s (%s)\n\n" % [start_port, end_port, @@transport]

        # Multiple targets in port scanner scope.
        if @@recursive === true
            # Convert IP netblock range to long format.
            netblock        = IPAddr.new(address)
            netblock_orig   = IPAddr.new(address.split('/').first)

            long_addr_first = netblock_orig.to_range.first.to_i
            long_addr_last  = netblock.to_range.last.to_i
            long_addr_last += 1

            # Test each IP address in range.
            until long_addr_first == long_addr_last do
                threads     = []
                threads_inc = 0

                # Convert back the long ip to string format.
                new_addr = IPAddr.new(long_addr_first, Socket::AF_INET).to_s

                # Scan the target with single port.
                if start_port == end_port
                    paddr = new_addr + ":" + start_port.to_s
                    print "  #{GB}> scanning addr:#{RST} %-22s\r" % [paddr]

                    _thread_request(new_addr, start_port, threads)

                    threads.each { |thr| thr.join }
                else
                    # Scan the target with each ports in range.
                    until start_port == end_port do
                        paddr = new_addr + ":" + start_port.to_s
                        print "  #{GB}> scanning addr:#{RST} %-22s\r" % [paddr]

                        _thread_request(new_addr, start_port, threads)

                        start_port  += 1
                        threads_inc += 1

                        if threads_inc == @@threads_limit.to_i || start_port >= end_port
                            threads.each { |thr| thr.join }
                            threads_inc = 0
                            threads = []
                        end
                    end
                end

                # Reset to the previous values.
                start_port  = @@start_port
                end_port    = @@end_port

                long_addr_first += 1
            end
        # Mirated target in port scanner scope.
        else
            threads     = []
            threads_inc = 0

            # Scan the target with single port.
            if start_port == end_port
                paddr = address + ":" + start_port.to_s
                print "  #{GB}> scanning addr:#{RST} %-22s\r" % [paddr]

                _thread_request(address, start_port, threads)

                threads.each { |thr| thr.join }
            # Scan the target with each ports in range.
            else
                until start_port == end_port do
                    paddr = address + ":" + start_port.to_s
                    print "  #{GB}> scanning addr:#{RST} %-22s\r" % [paddr]

                    _thread_request(address, start_port, threads)

                    start_port  += 1
                    threads_inc += 1

                    if threads_inc.to_i == @@threads_limit.to_i
                        threads.each { |thr| thr.join }
                        threads_inc = 0
                        threads = []
                    end
                end
            end
        end
        
        report_scan(false, true)
    end

    # Switch the transport scanner request.
    def _thread_request(address, port, threads)
        threads << Thread.new {
            if @@transport == 'tcp'
                _is_tcp_port_open?(address, port)
            else
                _is_udp_port_open?(address, port)
            end

            Thread.exit
        }
    end

    # Show the scanner report.
    def report_scan(dev = nil, scan = nil)
        disp = true

        # Loop through the modules and 
        # execute the context method.
        $modules.each { |m|
            if dev.nil?
                devices = @@report_list
            else
                devices = m.class_variable_get(:@@devices)
            end

            unless devices.empty?
                if disp === true
                    # Display resumed devices informations.
                    puts " " unless scan.nil?
                    puts " \n"
                    puts "  #{RST}----------------------------------------------------------------------------------------------------------------------"
                    puts "  | #{GB}%-16s #{RST}| #{GB}%-9s #{RST}| #{GB}%-40s #{RST}| #{GB}%-40s #{RST}|" % ['Device', 'Port', 'Banner', 'Allows']
                    puts "  #{RST}----------------------------------------------------------------------------------------------------------------------" 
                    disp = false
                end

                devices.each { |d| 
                    puts "  | %-16s | %-9s | %-40s | %-40s |" % [
                        d.first[:service_address], 
                        d.first[:service_port], 
                        d.first[:service_name], 
                        d.first[:service_methods][0..32]
                    ]
                
                    puts "  ----------------------------------------------------------------------------------------------------------------------"
                }

                unless dev.nil?
                    @@report_list.concat(devices)
                    @@report_list = @@report_list.uniq
                end

                m.class_variable_set(:@@devices, [])

                puts "  #{GB}+#{RST} Consider to use: #{GB}i [device] #{RST}to retrieve full device informations"
                print "\n"
            else
                print "\n\n  " unless dev.nil?
                puts "#{RB}+ note: #{RST}no one sip/iax result found."
                print "\n" unless dev.nil?
            end
        }
    end

    # Enumerate the sip extensions.
    def enum_extensions(command)
        command.shift

        unless command.empty?
            arguments  = command.take(2)
            range_file = arguments.first
            address    = arguments.last

            contents  = []

            # Parse the address or use the report list.
            if arguments.length == 1
                return puts "#{RB}- error:#{RST} no address specified or yet found in report list" if @@report_list.empty?
                address = @@report_list
            else
                return false unless valid_single_address?(address)
            end

            # Get and set the environment global variables.
            _set_transport
            _set_ports

            # Extensions range.
            if range_file.match(/^(\d{1,10}-\d{1,10})$/) 
                range = range_file.scan(/^(\d{1,10}-\d{1,10})$/).first.pop.split('-')

                if range.first.to_i < range.last.to_i
                    for i in range.first.to_i..range.last.to_i
                        contents << i
                    end
                else
                    for i in range.last.to_i..range.first.to_i
                        contents << i
                    end
                end

                _exec_enumeration(contents, address)
            # Extensions in file.
            else
                # Check the extensions file.
                if (contents = _organize_file_contents(range_file, 'extensions')) != false
                    _exec_enumeration(contents, address)
                end
            end
        else
            return puts "#{RB}- error:#{RST} use instead #{GB}enum [001-500|ext-file] [addr]#{RST}"
        end
    end

    # Live network traffic (sniffer-mode)
    def live(command)
        command.shift
        arguments = command.take(1)
        address   = arguments.first
        
        # Get the trasport and address if exists.
        if arguments.length < 1
            address = nil
        end

        # Get and set the environment global variables.
        _set_transport

        # Check for a valid address.
        if address != nil && address.length > 0
            if valid_single_address?(address) === false
                return false
            end
        end

        # Dispatch the transport.
        case @@transport
            when 'tcp' then _exec_intercept(address)
            when 'udp' then _exec_intercept(address)
            else
                puts "#{RB}- error:#{RST} use instead #{GB}live [udp|tcp]#{RST} or #{GB}live [udp|tcp] [addr]#{RST}"
        end
    end

    # Intercept the network traffic (sniffer-mode)
    def intercept(command)
        command.shift

        unless command.empty?
            _exec_intercept(nil, command)
        else
            puts "#{RB}- error:#{RST} use instead #{GB}intercept [pcap-filter]#{RST} or #{GB}h filters#{RST} to show the known filters"
        end
    end

    # Extension bruteforce.
    def bruteforce(command)
        command.shift

        unless command.empty? || command.length < 3
            arguments  = command.take(3)
            range_file = arguments.first
            psw_file   = arguments.at(1)
            address    = arguments.last

            contents   = []
            passwords  = []

            # Get and set the environment global variables.
            _set_transport
            _set_ports

            # Extensions range.
            if range_file.match(/^(\d{1,10}-\d{1,10})$/) 
                range = range_file.scan(/^(\d{1,10}-\d{1,10})$/).first.pop.split('-')

                if range.first.to_i < range.last.to_i
                    for i in range.first.to_i..range.last.to_i
                        contents << i
                    end
                else
                    for i in range.last.to_i..range.first.to_i
                        contents << i
                    end
                end
            # Extensions in file.
            else
                # Check the extensions file.
                if (contents = _organize_file_contents(range_file, 'extensions')) == false
                    return false
                end
            end

            # Check the password file.
            if (passwords = _organize_file_contents(psw_file, 'password')) != false
                return false unless valid_single_address?(address)
                _exec_bruteforce(address, contents, passwords)
            end
        else
            return puts "#{RB}- error:#{RST} use instead #{GB}bf [001-500|ext-file] [psw-file] [addr]#{RST}"
        end
    end

    # Return the extensions report.
    def report_extensions(address = nil, enum = nil)
        found = 0
        disp  = true
        list  = @@extensions_list

        unless enum.nil?
            list = enum
        end

        unless list.empty?
            list.each { |e|
                if disp === true
                    puts " "
                    puts "  ------------------------------------------------------------------------------------"
                    puts "  | #{GB}%-16s #{RST}| #{GB}%-9s #{RST}| #{GB}%-19s #{RST}| #{GB}%-4s #{RST}| #{GB}%-20s #{RST}|" % ['Device', 'Port', 'Extension', 'Auth', 'Password']
                    puts "  ------------------------------------------------------------------------------------"
                    disp = false
                end

                unless address.nil?
                    if e.first[:extension_address] == address
                        puts "  | %-16s | %-9s | %-18s  | %-4s | %-20s |" % [
                            e.first[:extension_address], 
                            e.first[:extension_port].to_s.downcase, 
                            e.first[:extension_value], 
                            e.first[:extension_auth]   === true ? 'yes' : 'no',
                            e.first[:extension_passwd] === false ? '' : e.first[:extension_passwd].to_s
                        ]
                        puts "  ------------------------------------------------------------------------------------"

                        found += 1
                    end
                else
                    puts "  | %-16s | %-9s | %-18s  | %-4s | %-20s |" % [
                        e.first[:extension_address], 
                        e.first[:extension_port].to_s.downcase, 
                        e.first[:extension_value], 
                        e.first[:extension_auth]   === true ? 'yes' : 'no',
                        e.first[:extension_passwd] === false ? '' : e.first[:extension_passwd].to_s
                    ]
                    puts "  ------------------------------------------------------------------------------------"

                    found += 1
                end
            }

            puts "\n" if enum.nil?
        end

        if found == 0
            print "\n   " unless address.nil?
            puts "#{RB}- error:#{RST} no information found about extensions"
            print "\n" unless address.nil?
        end

        return found
    end

    # Show the active session threads.
    def session(command)
        command.shift
        found = false

        unless command.empty? || command.length < 1
            thread_join = command.take(1).first.to_s
            thread_pos  = 1

            if thread_join == 'list'
                @@threads.each { |thr|
                    if thr.alive?
                        if found == false
                            found = true
                            puts "\n"
                        end

                        puts "  #{GB}- #{RST}session id: #{GB}%-2d\t#{RST}intercept detached in progress" % @@threads.index(thr)

                        thread_pos += 1
                    end
                }

                if found == false
                    return puts "- note: session table is empty"
                else
                    return puts "\n  #{GB}+ #{RST}Use #{GB}session [session_id] #{RST}to attach to process\n\n"
                end
            else
                @@threads.each { |thr|
                    if thr.alive?
                        if @@threads.index(thr) == thread_join.to_i
                            @@silent[thread_pos] = false

                            if found == false
                                found = true
                                puts "\n"
                            end

                            puts "  #{GB}- #{RST}session id: #{GB}%-2d\t#{RST}intercept detached in progress" % @@threads.index(thr)

                            begin
                                thr.join
                            rescue Interrupt
                                puts "\r\r  #{GB}+ #{RST}Packet Capture stopped by interrupt signal."
                                puts "  #{GB}%s#{RST} packets received by filter\n" % [@@capture[@@threads.index(thr)].stats['recv']]
                                puts "  #{GB}%s#{RST} packets dropped by kernel\n\n" % [@@capture[@@threads.index(thr)].stats['drop']]

                                @@capture[@@threads.index(thr)].close

                                @@silent.delete_at(thread_pos)
                                @@capture.delete_at(@@threads.index(thr))
                                @@threads.delete_at(@@threads.index(thr))
                            rescue Errno::EBADF
                                @@silent.delete_at(thread_pos)
                                @@capture.delete_at(@@threads.index(thr))
                                @@threads.delete_at(@@threads.index(thr))
                            end
                        end

                        thread_pos += 1
                    end
                }

                if found == false
                    return puts "#{RB}- error:#{RST} session was not found"
                end
            end
        else
            return puts "#{RB}- error:#{RST} use instead #{GB}session [list|session_id]#{RST}"
        end
    end

    # Decode on-the-fly the raw data-file with sox
    # and try to listen the captured voice-call.
    def decode(command)
        command.shift

        unless command.empty?
            arguments  = command.take(1)
            ret = _return_sox(arguments.first)

            if ret === false
                return puts "#{RB}- error:#{RST} sox is not installed?#{RST}" 
            elsif ret === true
                basename = File.basename(RAW_PATH + arguments.first, '.raw')
                puts "#{GB}- #{RST}decode: #{GB}%s#{RST} file have been decoded into: #{GB}raw/%s.wav#{RST}" % [arguments.first, basename]
            end
        end
    end

    private

    # Check for the udp open port, target informations
    # through custom modules and vulnerabilities
    # identification.
    def _is_udp_port_open?(address, port)
        socket = UDPSocket.new

        begin
            socket.connect(address, port)

            # Loop through the modules and 
            # execute the context method.
            $modules.each { |m|
                m.send('parse_udp', socket, address, port, @@timeout)
            }

            return true
        rescue Errno::EINVAL
            return false
        end
    end

    # Check for the tcp open port, target informations
    # through custom modules and vulnerabilities
    # identification.
    def _is_tcp_port_open?(address, port)
        begin
            Timeout::timeout(@@timeout) do
            begin
                socket = TCPSocket.new(address, port)

                # Loop through the modules and 
                # execute the context method.
                $modules.each { |m|
                    m.send('parse_tcp', socket, address, port)
                }

                socket.close
                return true
            rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::EINVAL
                return false
            end
        end
        rescue Timeout::Error
            return false
        end
    end

    # Execute the extensions enumeration.
    def _exec_enumeration(list, address)
        # Loop through the modules and 
        # execute the context method.
        $modules.each { |m| 
            # Address from the report list.
            if address.kind_of?(Array)
                address.each { |a|
                    address  = a.first[:service_address]
                    port  = a.first[:service_port].split('/').first
                    @@transport = a.first[:service_port].split('/').last.downcase

                    print "\n",
                        "  #{GB}starting enumeration on address:#{RST} \t%s\n" % [address], 
                        "  #{GB}using single port:#{RST}\t\t\t%s (%s)\n\n" % [port, @@transport]

                    if @@transport == 'udp'
                        socket = UDPSocket.new
                        socket.connect(address, port)
                    else
                        begin
                            Timeout::timeout(@@timeout) do
                            begin
                                socket = TCPSocket.new(address, port)
                            rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::EINVAL
                                break
                            end
                        end
                        rescue Timeout::Error
                            break
                        end
                    end

                    m.method('enum').call(socket, list, address, port, @@transport, @@timeout)
                    socket.close if socket != nil

                    print "\n"
                }
            # Address have been specified manually.
            else
                start_port = @@start_port
                end_port   = @@end_port

                print "\n",
                    "  #{GB}starting enumeration on address:#{RST} \t%s\n" % [address], 
                    "  #{GB}using ports-range:#{RST}\t\t\t%s-%s (%s)\n\n" % [start_port, end_port, @@transport]

                # If there is a single port, increments the
                # end port of range to do a correct until loop.
                if start_port === end_port
                    end_port += 1
                end

                until start_port == end_port do
                    if @@transport == 'udp'
                        socket = UDPSocket.new
                        socket.connect(address, start_port)
                    else
                        begin
                            Timeout::timeout(@@timeout) do
                            begin
                                socket = TCPSocket.new(address, start_port)
                            rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::EINVAL
                                break
                            end
                        end
                        rescue Timeout::Error
                            break
                        end
                    end

                    m.method('enum').call(socket, list, address, start_port, @@transport, @@timeout)
                    socket.close if socket != nil

                    start_port += 1
                end

                print "\n"
            end

            # Update the extensions list with last enumeration.
            extensions = m.class_variable_get(:@@extensions)
            unless extensions.empty?
                # Show the extensions report list.
                report_extensions(nil, extensions)

                @@extensions_list.concat(extensions)
                @@extensions_list = @@extensions_list.uniq
                m.class_variable_set(:@@extensions, [])
            end

            print "\n"
        }
    end

    # Execute the real network interception.
    def _exec_intercept(address = nil, filter = nil)
        _set_iface
        _set_dump

        custom = ''
        capture_len = @@capture.length

        # Open interface to capture network traffic.
        begin
            @@capture[capture_len] = PCAPRUB::Pcap.open_live(@@interface, PCAP_PACKET_SIZE, true, 0)
        rescue Exception => error
            return puts "#{RB}- error: #{RST}%s" % [error]
        end

        # Check for a custom filter (intercept).
        unless filter.nil?
            filter  = filter.join(' ')

            # Enable the authentication sniffing mode.
            if filter == 'password'
                filter = 'udp or tcp'
                custom = 'password'
            else
                # Check for the detached mode.
                if filter.include?('detach')
                    filter = filter.gsub(' detach', '')
                    custom += 'detach'
                end

                # Check if the stream needs to be write to the file.
                if filter.include?('record')
                    filter = filter.gsub(' record', '')
                    custom += 'record'
                end
            end

            # Set the custom filter.
            if (error = _set_bp_filter(@@capture[capture_len], filter)) != true
                return puts "#{RB}- error: #{RST} you have entered an invalid filter (%s)" % [error.message]
            end
        # No custom filter, do the live network capture (live).
        else
            filter = @@transport

            # Append address to the filter traffic by a target.
            unless address.nil?
                filter << ' and ip host ' << address
            end

            # Set the custom filter.
            if (error = _set_bp_filter(@@capture[capture_len], filter)) != true
                return puts "#{RB}- error: #{RST} you have entered an invalid filter (%s)" % [error.message]
            end
        end

        print "\n",
            "  #{GB}capturing local network traffic#{RST}\n",
            "  #{GB}using barkeley packet filter:#{RST}\t%s\n\n" % [filter],
            "  #{RB}note: #{RST}the unneeded frame bytes will be skipped by the parser\n\n"

        # Loop through the packets.
        begin
            # Open packet capture in thread
            # to prevent an heap overflow that
            # occurs using pcap library along 
            # with ruby threads.
            @@threads << Thread.new {
                if @@capture[capture_len]
                    @@capture[capture_len].each_packet { |packet|
                        _print_packet(packet, custom, capture_len)
                    }
                end

                Thread.exit
            }

            # Check for the background session.
            if custom.include?('detach')
                @@silent[capture_len] = true
                @@threads.last.run
            else
                @@silent[capture_len] = false
                @@threads.last.join
            end
        rescue Interrupt
            puts "\r\r  #{GB}+ #{RST}Packet Capture stopped by interrupt signal."
            puts "  #{GB}%s#{RST} packets received by filter\n" % [@@capture[capture_len].stats['recv']]
            puts "  #{GB}%s#{RST} packets dropped by kernel\n\n" % [@@capture[capture_len].stats['drop']]

            @@capture[capture_len].close
            @@silent.delete_at(capture_len)
            @@capture.delete_at(capture_len)
            @@threads.delete_at(capture_len)
        rescue Exception => error
            puts "\n  - error: #{error}"
            retry
        end
    end

    # Print packet data skipping unneeded frame bytes.
    def _print_packet(packet, custom, capture_len)
        top_line_frame = true

        packet.data.to_s.each_line { |line|
            # Base intercept.
            if custom.length == 0
                if top_line_frame == true
                    packet_info = "\n  Packet length: %s, Time: %s" % [
                        packet.length,
                        Time.at(packet.time).strftime('%F %T')
                    ]

                    print packet_info << "\n  "
                    (packet_info.length - 5).times {
                        print '-'
                    }

                    _dump(line, top_line_frame, capture_len)
                else
                    _dump(line, top_line_frame, capture_len)
                end

                top_line_frame = false
            # Sniff md5 challenge response hash.
            else
                # Try to parse the authentication phase.
                if custom.include?('password')
                    # Loop through the modules and 
                    # execute the context method.
                    $modules.each { |m|
                        m.send('parse_password', line, Time.at(packet.time).strftime('%F %T'))
                    }
                else
                    if top_line_frame == true
                        _dump(line, top_line_frame, capture_len)
                    else
                        _dump(line, top_line_frame, capture_len)
                    end

                    top_line_frame = false

                    # Write the raw stream data to file (byte-to-byte).
                    if custom.include?('record')
                        File.open(RAW_PATH + PCAP_RAW_FILE, 'ab') { |f|
                            line.each_byte { |b| f << b.chr }
                        }
                    end
                end
            end
        }
    end

    # Dump the packet.
    def _dump(line, top, capture_len)
        if @@silent[capture_len] === false
            if top === true
                # Check for the hexadecimal dump.
                if @@dump_hex == 'on'
                    puts "\n"
                    line.each_byte { |x| 
                        print "%0.2x " % x 
                    }
                else
                    # The first 44 bytes of UDP model indicates
                    # UDP Header -> IP Header -> Padding
                    # so skip them.
                    if @@dump_clean == 'on'
                        puts "\n  %s" % [line.to_s[44..line.length]]
                        # puts "\n  %s" % [line.to_s.split(/\(hex\)\s*/n).last]
                    else
                        puts "\n  %s" % line.to_s
                    end
                end
            else
                # Check for the hexadecimal dump.
                if @@dump_hex == 'on'
                    puts "\n"
                    line.each_byte { |x| 
                        print "%0.2x " % x 
                    }
                else
                    puts "  %s" % line.to_s
                end
            end
        end
    end

    # Execute the bruteforcer.
    def _exec_bruteforce(address, list, passwords)
        # Loop through the modules and 
        # execute the context method.
        $modules.each { |m|
            disp = true

            list.each { |l| 
                start_port = @@start_port
                end_port = @@end_port

                if disp == true
                    print "\n",
                        "  #{GB}starting bruteforce on address:#{RST} \t%s\n" % [address], 
                        "  #{GB}using ports-range:#{RST}\t\t\t%s-%s (%s)\n\n" % [start_port, end_port, @@transport]

                    disp = false
                end

                # If there is a single port, increments the
                # end port of range to do a correct until loop.
                if start_port === end_port
                    end_port += 1
                end

                until start_port == end_port do
                    if @@transport == 'udp'
                        socket = UDPSocket.new
                        socket.connect(address, start_port)
                    else
                        begin
                            Timeout::timeout(@@timeout) do
                            begin
                                socket = TCPSocket.new(address, start_port)
                            rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::EINVAL
                                break
                            end
                        end
                        rescue Timeout::Error
                            break
                        end
                    end

                    unless socket.nil?
                        m.method('bruteforce').call(socket, l, address, start_port, passwords, @@transport, @@timeout)
                        socket.close
                    end

                    start_port += 1
                end
            }

            # Update extensions list with last enumeration.
            extensions = m.class_variable_get(:@@extensions)

            unless extensions.empty?                
                # Show the extensions report list.
                report_extensions(nil, extensions)

                @@extensions_list.concat(extensions)
                @@extensions_list = @@extensions_list.uniq
                m.class_variable_set(:@@extensions, [])
            end

            print "\n"
        }
    end

    # Organize the file contents in array.
    def _organize_file_contents(filename, what)
        tmp = []

        # Get the password list.
        if File.exist?(LISTS_PATH + filename)
            begin
                if File.open(LISTS_PATH + filename).each { |line| 
                        tmp << line.strip
                    }
                end
            rescue Exception
                puts "#{RB}- error:#{RST} #{what} list is not readable or file is empty"
                return false
            end
        else
            case what
                when 'password'     then puts "#{RB}- error:#{RST} #{what} file doesn't exists"
                when 'extensions'   then puts "#{RB}- error:#{RST} invalid extensions list file or malformed range"
            end
            return false
        end

        return tmp
    end

    # Set the dump global variables.
    def _set_dump
        # Checks for dumphex option.
        if ENV.key?(ENV_PREFIX + 'DUMPHEX')
            @@dump_hex = ENV.fetch(ENV_PREFIX + 'DUMPHEX')
        end

        # Check for the dumpclean option.
        if ENV.key?(ENV_PREFIX + 'DUMPCLEAN')
            @@dump_clean = ENV.fetch(ENV_PREFIX + 'DUMPCLEAN')
        end
    end

    # Set the threads limit global variable.
    def _set_threads_limit
        # Check for the timeout option.
        if ENV.key?(ENV_PREFIX + 'THREADS')
            @@threads_limit = ENV.fetch(ENV_PREFIX + 'THREADS').to_i
        end
    end

    # Set the timeout global variable.
    def _set_timeout
        # Check for the timeout option.
        if ENV.key?(ENV_PREFIX + 'TIMEOUT')
            @@timeout = ENV.fetch(ENV_PREFIX + 'TIMEOUT').to_f
        end
    end

    # Set the interface global variable.
    def _set_iface
        # Check for the network interface.
        if ENV.key?(ENV_PREFIX + 'IFACE')
            @@interface = ENV.fetch(ENV_PREFIX + 'IFACE')
        end
    end

    # Set the transport global variable.
    def _set_transport
        # Check and parse the transport.
        if ENV.key?(ENV_PREFIX + 'TRANSPORT')
            @@transport = ENV.fetch(ENV_PREFIX + 'TRANSPORT').downcase
        end
    end

    # Set the ports global variables.
    def _set_ports
        # Check and parses the port scan range.
        if ENV.key?(ENV_PREFIX + 'PORT')
            ports = ENV.fetch(ENV_PREFIX + 'PORT')
            if ports.include?('-')
                ports = ports.split('-')
        
                @@start_port = Integer ports.first
                @@end_port = Integer ports.last
            else
                @@start_port = Integer ports
                @@end_port = Integer ports
            end
        end
    end

    # Set a barkeley packet filter.
    def _set_bp_filter(descriptor, filter)
        begin
            descriptor.setfilter(filter)
            return true
        rescue Exception => error
            return error
        end

        return false
    end

    # Test if sox command exists.
    def _return_sox(filename)
        if File.exist?(RAW_PATH + filename)
            return system("#{BASH_PATH} -c 'sox -r8000 -c1 -t ul #{RAW_PATH}#{filename} -t wav #{RAW_PATH}`basename #{filename} .raw`.wav &> /dev/null'")
        else
            return puts "#{RB}- error:#{RST} #{RAW_PATH}#{filename} file doesn't exists"
        end
    end
end
