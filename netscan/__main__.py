import sys
from .netscan import Netscan

import argparse    
def main():
    parser = argparse.ArgumentParser(description='A Simple Network Scanning Utility')
    parser.add_argument('-v','--version',help='print version.',action='store_true')
    parser.add_argument('-nS',help='lists active devices on a network.',action='store_true')
    parser.add_argument('-ip',metavar='{Ip Address}',type=str,default=False,help='add an ip address in the network to scan its ports.')
    args = parser.parse_args()
    # print(args)
    netscan = Netscan()
    try:
        if args.version:
            print('\tNetscan version 0.1.0')
            sys.exit()
        nS = netscan.NetworkScan()
        if args.nS:
            nS.printResults()
            sys.exit()
        elif args.ip:
            if args.ip in nS.list_of_ip:
                netscan.Questions().GetPortRange(args.ip)
            else:
                print("I'm sorry the IP you entered is not in the the network")
            sys.exit()
        else:
            netscan.CheckConnection()
    except KeyboardInterrupt:
        print('\n[*]Exiting Program...')

if __name__ == '__main__':
    main()