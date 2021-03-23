from threading import Thread, Lock
from queue import Queue
import time
import socket
from colorama import init, Fore
#from .__main__ import ne
# some colors
init()
GREEN = Fore.GREEN
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX
CYAN = Fore.CYAN
RED = Fore.RED
YELLOW = Fore.LIGHTYELLOW_EX


class Netscan:
    def __init__(self):
        from pyfiglet import Figlet
        print(f'{GREEN}',Figlet(font='slant').renderText('Netscan'),f'{RESET}','-'*37)

        hostname = socket.gethostname()
        Netscan.hostIp = socket.gethostbyname_ex(hostname)
        print("\nIP Address for "+YELLOW+hostname+RESET+"(this machine) is -> "+YELLOW+Netscan.hostIp[-1][-1]+RESET+"\n")

    #-----------------------Port Scan-----------------------#
    class PortScan:


        def __init__(self,ports):
            No_of_Threads = 100
            self.Q = Queue()
            self.print_lock = Lock()
            self.count = 0
            for _ in range(No_of_Threads):
                th = Thread(target=self.Threading)
                th.daemon = True
                th.start()
            start_time = time.time()
            try:
                for p in ports:
                    self.Q.put(p)
            except:
                self.Q.put(ports)
            self.Q.join()
            print('    '*10+'\n',end='\r')
            end_time = time.time()
            if self.count == 0:
                try:
                    print(Netscan.Port_range[0]+"-"+Netscan.Port_range[1]+" -> No ports open")
                except:
                    print(Netscan.Port_range[0]+" -> closed")
                finally:
                    print('\n')


            print(f'Time taken {end_time-start_time:.2f} seconds')
            print('\n  '+'-'*37)
            exit()

        def Scan(self,port):
            #self.Ipaddr = Netscan.Questions.answers['CheckIpAddress']
            try:
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((Netscan.Ipaddr,port))
            except socket.error:
                return False
            return True


        def Threading(self):
            major_ports = {
            "21":"FTP",
            "22":"SSH",
            "23":"TELNET",
            "25":"SMTP",
            "53":"DNS",
            "80":"HTTP",
            "110":"POP3",
            "111":"RPCBIND",
            "119":"NNTP",
            "123":"NTP",
            "135":"MSRPC",
            "139":"NETBIOS-SSN",
            "143":"IMAP",
            "161":"SNMP",
            "194":"IRC",
            "443":"HTTPS",
            "445":"MICROSOFT-DS",
            "993":"IMAPS",
            "995":"POP3S",
            "1723":"PPTP",
            "3306":"MYSQL",
            "3389":"MS-WBT-SERVER",
            "5900":"VNC",
            "8080":"HTTP-PROXY"
        }
            while True:
                p = self.Q.get()
                if self.Scan(p):
                    self.count = 1
                    if str(p) in major_ports:
                        with self.print_lock:
                            print(f"{GREEN}{str(p):5} -> {major_ports[str(p)]:5} -> open   {RESET}")
                    else:
                        with self.print_lock:
                            print(f"{GREEN}{str(p):5} -> open   {RESET}")
                else:
                    with self.print_lock:
                        print(f"{GRAY}{str(p):5} -> closed  {RESET}", end='\r')
                self.Q.task_done()
    

    #-----------------------Network/Ping Scan-----------------------#
    class NetworkScan:
        def __init__(self):
            from scapy.all import ARP, Ether, srp
            arp = ARP(pdst=Netscan.hostIp[-1][-1]+"/24")
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=1, verbose=0)[0]

            self.clients = []
            self.list_of_ip = []

            for sent, received in result:
                self.clients.append({'ip': received.psrc, 'mac': received.hwsrc})
                self.list_of_ip.append(received.psrc)


        def printResults(self):
            if self.clients:
                print("\nAvailable devices in the network:")
                print(YELLOW+"IP" + " "*18+"MAC"+RESET)
                for client in self.clients:
                    print("{:16}    {}".format(client['ip'], client['mac']))
            else:
                print("No active devices in your network :(\nCheck your connection and try again")
                return False
            print('\n')

    #-----------------------Questions-----------------------#

    class Questions:
        def GetPortRange(self):
            print("Enter "+YELLOW+"range of ports"+RESET+" to scan: "+CYAN+"Format: 'from - to' "+GRAY+"\tDefault 1000 ports"+RESET)
            Netscan.Port_range = input("\t=> ").split("-")
            if (0 < len(Netscan.Port_range) <= 2):
                for blank in Netscan.Port_range:
                    if blank == '':
                        Netscan.Port_range.remove(blank)
                if len(Netscan.Port_range) == 0:
                    self.ports = [p for p in range(1,1001)]
                elif len(Netscan.Port_range) == 1:
                    self.ports = int(Netscan.Port_range[0])
                else:
                    Port_start_range , Port_end_range = Netscan.Port_range
                    self.ports = [p for p in range(int(Port_start_range),int(Port_end_range)+1)]
                Netscan.PortScan(self.ports)

            else:
                print(f"{RED}ERROR: Please ensure that you have entered the port range or single port in the given format{RESET}")


        def __init__(self):
            self.networkscan = Netscan.NetworkScan()
            from PyInquirer import Validator, ValidationError
            from PyInquirer import style_from_dict, Token, prompt


            style = style_from_dict({
                Token.QuestionMark: '#E91E63 bold',
                Token.Selected: '#673AB7 bold',
                Token.Instruction: '',  # default
                Token.Answer: '#2196f3 bold',
                Token.Question: '',
            })

            
            questions = [
                {
                    'type': 'confirm',
                    'name': 'printPingScan',
                    'message': 'Do you want to list active IP addresses on the network?',
                    'default': False
                },
                {
                    'type': 'list',
                    'name': 'CheckIpAddress',
                    'message': 'Select one or more Ip address to run a Simple Port Scan on them.',
                    'choices': self.networkscan.list_of_ip + ['Cancel/Exit Scan'],
                },
            ]

            
            self.answers = prompt(questions[0], style=style)
            if self.answers['printPingScan'] == True:
                self.networkscan.printResults()
            time.sleep(1)
            questions.pop(0)     
            self.answers = prompt(questions, style=style)
            Netscan.Ipaddr = self.answers['CheckIpAddress']
            if Netscan.Ipaddr == 'Cancel/Exit Scan':
                exit()
            else:
                self.GetPortRange()

            
            

            
    #-----------------------Check Internet Connection-----------------------#

    def CheckConnection(self,Netscan):
        self.Netscan = Netscan
        import urllib.request
        if urllib.request.urlopen('http://google.com'):
            Netscan.Questions()
            exit
        else:
            print(f"{RED}ERROR: There seems to be a problem with your internet connection x_x{RESET}")
            if len(input("Press Enter to try again\n")) >= 0:
                Netscan.CheckConnection()
            else:
                print("I'm Sorry, There seem's to be a problem\nHope you have a better experience next time!!")
                exit
            
        
