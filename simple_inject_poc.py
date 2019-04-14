import os
import sys
import argparse
import ctypes # should set up error handling for this import 

PTRACE_POKEDATA   = 5   # used for injecting into process
PTRACE_ATTACH     = 16  # used for attaching to the process 
PTRACE_DETACH     = 17  # used for detaching

# need to check for exists(libc path) on system, using hard coded for testing
# parse /proc/pid/maps of current process to get libc :) 
libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')

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


def main(args):
    
    if not ptrace_check():
        sys.exit()       
    
    pid = args.p

    # attach to process 
    libc.ptrace(PTRACE_ATTACH, pid , None, None)
    status = os.waitpid(pid, 0)
    if os.WIFSTOPPED(status[1]):
        if os.WSTOPSIG(status[1]) == 19:
            print("attached to process")
        else:
            print("Unabe to attach - stopped for something else ?  {}").format(os.WSTOPSIG(status[1]))
            sys.exit(1)







if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A script to take advantage of Sudo')
    parser.add_argument('-p', action="store", default=None, help="pid to inject", required=True, type=int)
    parser.add_argument('--payload', action="store", default='echo "hello world"', help="command to run in process")
    args = parser.parse_args()
    main(args)
