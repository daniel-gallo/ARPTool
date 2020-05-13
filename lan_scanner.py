from typing import Dict, List

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def get_manufacturer(manufacturers: Dict[str, str], mac_address: str) -> str:
    """
    Gets the manufacturer of the mac address mac_address consulting manufacturers
    :param manufacturers: a dictionary with pairs (mac address - manufacturer)
    :param mac_address
    :return: manufacturer of the mac address if found or "Unknown manufacturer"
    """
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
        # Two devices are the same iff they have the same ip
        return self.ip_address == other.ip_address

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        return f"{self.ip_address}\t{self.mac_address}\t{self.manufacturer}"


def get_devices(netmask: str, timeout: float, manufacturers: Dict[str, str] = None) -> List[Device]:
    """
    Performs an ARP scan of the local network
    :param netmask: netmask of the LAN in CIDR format, like 192.168.1.1/24
    :param timeout: time limit of the scan in seconds
    :param manufacturers: if provided, devices will include the manufacturer (if known)
    :return: a list of the devices found
    """
    answers, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=netmask), timeout=timeout, verbose=False)
    return [Device(ip_address=answer[1].psrc,
                   mac_address=answer[1].src,
                   manufacturers=manufacturers) for answer in answers]
