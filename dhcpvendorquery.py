from scapy.all import *
import getmac
import random
import time

def create_dhcp_discover(mac, vendor_class):
    xid = random.randint(1, 0xFFFFFFFF)
    
    dhcp_discover = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")\
                /IP(src="0.0.0.0", dst="255.255.255.255")\
                /UDP(sport=68, dport=67)\
                /BOOTP(chaddr=mac2str(mac), xid=xid)\
                /DHCP(options=[("message-type", "discover"), 
                                ("vendor_class_id", vendor_class),
                                "end"])

    return dhcp_discover

def create_dhcp_request(mac, vendor_class, server_id, offered_ip, xid):
    dhcp_request = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")\
                /IP(src="0.0.0.0", dst="255.255.255.255")\
                /UDP(sport=68, dport=67)\
                /BOOTP(chaddr=mac2str(mac), xid=xid, ciaddr="0.0.0.0")\
                /DHCP(options=[("message-type", "request"), 
                                ("server_id", server_id),
                                ("requested_addr", offered_ip),
                                ("vendor_class_id", vendor_class),
                                "end"])
    return dhcp_request

def create_dhcp_release(mac, server_id, client_ip):
    dhcp_release = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")\
                /IP(src="0.0.0.0", dst="255.255.255.255")\
                /UDP(sport=68, dport=67)\
                /BOOTP(chaddr=mac2str(mac), ciaddr=client_ip)\
                /DHCP(options=[("message-type", "release"), 
                                ("server_id", server_id),
                                "end"])
    return dhcp_release

def send_dhcp_discover(dhcp_discover):
    response = srp1(dhcp_discover, filter="udp and (port 67 or 68)", timeout=3, iface_hint='0.0.0.0')
    return response

def send_dhcp_request(dhcp_request):
    response = srp1(dhcp_request, filter="udp and (port 67 or 68)", timeout=3, iface_hint='0.0.0.0')
    return response

def send_dhcp_release(dhcp_release):
    sendp(dhcp_release, iface_hint='0.0.0.0')

def display_dhcp_response(response):
    if response is None:
        print("No DHCP response received.")
        return
    
    for option in response[DHCP].options:
        if option[0] == "end":
            break
        
        print(f"Option: {option[0]} Value: {option[1]}")

def random_mac():
    return ":".join(["%02x" % random.randint(0x00, 0xFF) for _ in range(6)])

if __name__ == "__main__":
    mac = input("Enter MAC address (blank for system MAC, 'r' for random MAC, format: AA:BB:CC:DD:EE:FF): ").strip()
    if mac.lower() == 'r':
        mac = random_mac()
    else:
        mac = mac or getmac.get_mac_address()
        
    vendor_class = input("Enter vendor class (blank for default 'NECDT700'): ").strip() or "NECDT700"

    print(f"Using MAC address: {mac}")
    print(f"Using vendor class: {vendor_class}")

    dhcp_discover = create_dhcp_discover(mac, vendor_class)
    offer = send_dhcp_discover(dhcp_discover)
    server_id, offered_ip, xid = None, None, None

    if offer is None:
        print("No DHCP offer received.")
    else:
        print("DHCP Offer details:")
        display_dhcp_response(offer)
        
        for opt in offer[DHCP].options:
            if opt[0] == 'server_id':
                server_id = opt[1]
            elif opt[0] == 'yiaddr':
                offered_ip = opt[1]
            elif opt[0] == 'xid':
                xid = opt[1]
                
        if server_id and offered_ip:
            dhcp_request = create_dhcp_request(mac, vendor_class, server_id, offered_ip, xid)
            response = send_dhcp_request(dhcp_request)

            print("\nDHCP Response details:")
            display_dhcp_response(response)

            time.sleep(2)
            
            dhcp_release = create_dhcp_release(mac, server_id, offered_ip)
            send_dhcp_release(dhcp_release)
            print("\nSent DHCP Release for IP: ", offered_ip)
