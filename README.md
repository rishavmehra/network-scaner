 import scapy.all as scapy
import optparse
import subprocess

def get_arguments():
     parser = optparse.OptionParser()
     parser.add_option("-t", "--target", dest="target", help="target IP/IP range")
     (option,arguments) = parser.parse_args()
     return option
def scan(ip):
     arp_request = scapy.ARP(pdst=ip)
     broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
     arp_request_broadcast = broadcast/arp_request
     answered_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]
     client_list = []
     for element in answered_list:
          client_dict = {"ip": element[1].psrc, "mac":  element[1].hwsrc}
          client_list.append(client_dict)
     return client_list
def print_result (result_list):
     print("ip \t\t\t mac address\n ---------------------------------------------")
     for client in result_list:
          print(client["ip"] + "\t\t" + client["mac"])

option = get_arguments()
scan_result = scan("10.0.2.2/24")
print_result(scan_result)

