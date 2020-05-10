from threading import Lock
from time import sleep
from typing import Dict, List, Callable

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def get_manufacturer(manufacturers: Dict[str, str], mac_address: str) -> str:
    if mac_address[:8] in manufacturers:
        return manufacturers[mac_address[:8]]
    elif mac_address[:10] in manufacturers:
        return manufacturers[mac_address[:10]]
    elif mac_address[:13] in manufacturers:
        return manufacturers[mac_address[:13]]
    else:
        return "Unknown manufacturer"


class Device:
    def __init__(self, ip_address: str, mac_address: str, manufacturers: Dict[str, str] = None):
        self.ip_address = ip_address
        self.mac_address = mac_address
        if manufacturers:
            self.manufacturer = get_manufacturer(manufacturers, self.mac_address)
        else:
            self.manufacturer = None

    def __lt__(self, other):
        # Sort by IP. Note that alphabetical order != IP order. Thus, the IP string must be converted to an int tuple
        return tuple(map(int, self.ip_address.split('.'))) < tuple(map(int, other.ip_address.split('.')))

    def __eq__(self, other):
        # Two devices are the same iff they have the same ip and mac address
        return self.ip_address == other.ip_address and self.mac_address == other.mac_address

    def __hash__(self):
        return hash(str(self))

    def __str__(self):
        return f"{self.ip_address}\t{self.mac_address}\t{self.manufacturer}"


def discoverer(cidr: str, devices_list: List[Device], mutex: Lock, print_function: Callable, frequency: float):
    manufacturers = {}
    with open("manufacturers.txt") as f:
        for line in f:
            mac, manufacturer_name = tuple(line.strip().split('\t'))
            manufacturers[mac] = manufacturer_name

    while True:
        answers, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr), timeout=.5, verbose=False)
        devices = [Device(ip_address=answer[1].psrc,
                          mac_address=answer[1].src,
                          manufacturers=manufacturers) for answer in answers]

        with mutex:
            devices_list.extend(device for device in devices if device not in devices_list)
            devices_list.sort()
        print_function()

        sleep(frequency)
