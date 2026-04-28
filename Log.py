from termcolor import colored # pip3 install termcolor
import sys
class Log:
    
    # Static verbose property
    verbose_enabled = False

    @staticmethod
    def abort(msg):
        print(f"[!] {colored(msg, 'red')}")
        sys.exit(1)

    @staticmethod
    def warn(msg):
        msg = "[!] " + msg
        print(colored(msg, 'yellow'))

    @staticmethod
    def verbose(msg):
        if Log.verbose_enabled:
            msg = "[*] " + msg
            print(colored(msg, 'cyan'))

    @staticmethod
    def info(msg, prefix = "[*] "):
        msg = prefix + msg
        print(msg)