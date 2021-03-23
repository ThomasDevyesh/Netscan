import sys
from .netscan import Netscan


version = 'Netscan version 0.1.0'
output = "\n\tA Simple Network Scanning Utility"
help = "\nhelp needed"
help += "\neg.\tnetscan\n\tnetscan -h"



def main():
    try:
        args = sys.argv[1:]
    finally:
        if len(args) == 0:
            netscan = Netscan()
            netscan.CheckConnection(netscan)
        elif len(args) >= 1:
            if args[0] == '-h' or args[0] == '--help':
                global output
                print(version+output+help)
            elif args[0] == '-v' or args[0] == '--version':
                print(version)
            else:
                output += "\nPress '-h' or '--help for help'"
                print(version+output)


if __name__ == '__main__':
    main()