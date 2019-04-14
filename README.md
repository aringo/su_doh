# su_doh
Script for owning a system that runs sudo, project is a working basis for a metasploit module to do the same

```
usage: su_doh.py [-h] [-b] [-i] [-d] [-p P] [--payload PAYLOAD] [-f F]

A script to take advantage of Sudo

optional arguments:
  -h, --help         show this help message and exit
  -b                 backdoor bashrc to launch payload as sudo next time
  -i                 try to inject into a running sudo process and run a
                     privileged command
  -d                 payload that will allow you to sudo with no passwd in any
                     terminal forever
  -p P               pid that ran sudo - to be used with -i, otherwise will
                     bruteforce shells
  --payload PAYLOAD  location of payload on disk to run
  -f F               optional name for file created in sudoers.d from payload
                     created by -d
```
The program generates a default payload to turn off tty tickets, this will enable a sudo session to escape the 
jailed terminal a user ran the sudo command in.  Next the payload will turn off the timeout limits that sudo can 
be run as long as they would like without a password

There is currently two modes the script runs in.

    Inject - into a process that is running sudo and run a payload as root.  

    Backdoor - the users .bashrc so that the next time they run sudo it runs the payload as root.

If injection is selected the script will run a ptrace check to see if the system allows users to ptrace their own processes. 

On systems with yama ptrace /proc/sys/kernel/yama/ptrace_scope must be 0 
On systems with selinux deny_ptrace must be not on 

Next it will try to inject into the given pid.  If no pid is given the program will attempt to inject in all processes.







