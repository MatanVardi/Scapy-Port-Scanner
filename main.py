import ipaddress
from scapy.layers.inet import *

open_ports = []
port_range = 1024

def main():
    destination_ip = input("Please enter a destination Ip address: ")
    port_number = 0

    if check_valid_ip(destination_ip):
        while port_number < port_range:
            packet = IP(dst=destination_ip)/TCP(sport=44444, dport=port_number, flags="S")
            response = sr1(packet, timeout=2, verbose=0)
            print(response)
            if response is not None:
                if response.haslayer(TCP):
                    if response.getlayer(TCP).flags == "SA":
                        open_ports.append(response[TCP].sport)
                        print(f"Port {port_number} is open\n")
                    elif response.getlayer(TCP).flags == "RA":
                        print(f"Port {port_number} is closed\n")

                elif response.haslayer(ICMP):
                    if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                        print(f"Port {port_number} is filtered\n")
            else:
                print("Response is None")
            port_number += 1
def check_valid_ip(internet_protocol_string):
    try:
        ipaddress.ip_address(internet_protocol_string)
        return True
    except ValueError:
        return False

if __name__ == '__main__':
    main()