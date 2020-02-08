import argparse as argparse
import scapy.all as scapy
import argparse
#from mac_vendor_lookup import MacLookup

# print(MacLookup().lookup("98:ED:5C:FF:EE:01"))
def set_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--Range", dest="range", help="Set network range")
    Option = parser.parse_args()
    return Option
def scan(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_request = broadcast/arp_request
    answered = scapy.srp(broadcast_request, timeout=1)[0]
    # print(answered.summary())


    Client_list = []
    print("\t IP \t\t\t\t\tMAC ADDRESS")
    print("--------------------------------------------")

    for element in answered:
        client_dict ={"ip":element[1].psrc,"mac":element[1].hwsrc}
        Client_list.append(client_dict)
        element[1].psrc + "\t\t\t" + element[1].hwsrc


    return Client_list

def dict_scan(result_list):
    for element1 in result_list:

        print(element1["ip"] + "\t\t\t" + element1["mac"])

    print("--------------------------------------------")


option = set_arguments()
scan_result=scan(option.range)
dict_scan(scan_result)