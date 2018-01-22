vsaudit
=======

This is an opensource tool to perform attacks to general voip services It allows to scans the whole network or single host to do the gathering phase, then it is able to search for most known vulnerabilities on the founds alive hosts and try to exploit them.


Install dependencies
--------------------

To start using vsaudit you must install the 'bundler' package that will be used to install
the requireds gem dependencies through the Gemfile.

Download directly from website: 

    http://bundler.io/

Or install with 'gem' (ruby package manager) with: 

    deftcode ~ $ gem install bundler

After that the installation has been completed, run (in the directory where is located vsaudit):

    deftcode vsaudit $ bundle

Now you can start vsaudit with:

    deftcode vsaudit $ ruby vsaudit.rb

NOTE: If you get an error with gem, you need to install the ruby-dev and libssl-dev packages (kali-linux: apt install ruby-dev libssl-dev).


Environment commands
--------------------

- Display the available options that can be set
- List the environment variables
- Get the value of environment variable
- Set or change the environment variables


Audit commands
--------------

- Check mistakes in the local configuration files
- Scan a local o remote network
- Enumerate the extensions
- Bruteforce extensions
- Get the live network traffic
- Intercept the network traffic by custom bpf


Informations commands
---------------------

- Get informations about modules or address
- Show the report list
- Show the extensions list


Global commands
---------------

- Display the help message
- Quit from the framework


Screenshots
-----------

![vsaudit - scanner](https://raw.githubusercontent.com/orgdeftcode/vsaudit/master/screens/preview-1.png)

![vsaudit - enumeration](https://raw.githubusercontent.com/orgdeftcode/vsaudit/master/screens/preview-2.png)

![vsaudit - bruteforce](https://raw.githubusercontent.com/orgdeftcode/vsaudit/master/screens/preview-3.png)

![vsaudit - intercept](https://raw.githubusercontent.com/orgdeftcode/vsaudit/master/screens/preview-4.png)


Reference
---------

* Manual: http://deftcode.ninja/post/vsaudit-voip-security-audit-framework
* RFC-3261 (SIP - Session Initiation Protocol): https://www.ietf.org/rfc/rfc3261.txt
