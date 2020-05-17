from ipaddress import IPv4Network
from shutil import which
from os import system, getuid
from typing import Tuple

import netifaces
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr


def get_gateway_information() -> Tuple[str, str, str]:
    """
    Gets information about the default gateway
    :return: (gateway_ip, gateway_mac, netmask) where netmask follows the CIDR notation
    """
    gateway_ip, interface = netifaces.gateways()["default"][netifaces.AF_INET]
    netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["netmask"]
    mask_bits = IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    cidr = f"{gateway_ip}/{mask_bits}"
    ans, _ = sr(ARP(op="who-has", pdst=gateway_ip), verbose=False)
    gateway_mac = ans[0][1].hwsrc

    return gateway_ip, gateway_mac, cidr


def show_notification(title: str, message: str):
    """
    Shows a notification on screen. At the moment it only supports macOS notification, since Linux's notify-send
    won't work when run as root.
    :param title: title of the notification
    :param message: message of the notification
    """
    if which("osascript"):
        system(f"osascript -e 'display notification \"{message}\" with title \"{title}\"'")
    # elif which("notify-send"):
    #     system(f"notify-send '{title}' '{message}'")
    else:
        print(f"[{title}] {message}")


def check_root():
    if getuid() != 0:
        print("You have to run this script as root")
        exit(1)
