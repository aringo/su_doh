# su_doh
Script for owning a system that runs sudo

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
be run as long as they would like without a password.

This payload could be apparent if the user runs a sudo -l as that show the current environment and they also would be able to run sudo in any terminal without password.

There is currently two modes the script runs in.

    Inject - into a process that is running sudo and run a payload as root.  

    Backdoor - the users .bashrc so that the next time they run sudo it runs the payload as root.

### Injection mode 
If injection mode is selected the script will run a ptrace check to see if the system allows users to ptrace their own processes. 
```
On systems with yama ptrace /proc/sys/kernel/yama/ptrace_scope must be 0 
On systems with selinux deny_ptrace must be not on 
```
Next it will check to see if gdb exists and then it will try to inject into a given pid.  If no pid is given the program will attempt to inject in all processes that meet a regex of a shell.

There is a risk of causing a sudo password error if the processes have not run a password session.  Additionally this should not work in a container environment (docker)as CAP_SYS_PTRACE is not available no matter what user you are.

### Backdoor mode 
If backdoor mode is selected the script will simply add a line to the users bashrc so the next time they run sudo the payload is executed. If the user action may be after a reboot the default payload directory should be changed to something that will persist.    







