import argparse
from time import sleep
from typing import Optional

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sniff

from mitm import get_arp_cache
from utils import check_root, show_notification


def get_mac(ip: str, timeout: int = 1) -> Optional[str]:
    """
    Gets the MAC address of a given IP address
    :param ip: IP address
    :param timeout: maximum time this function will take
    :return: a string with the MAC address of the provided IP address if found. If not, None will be returned.
    """
    from scapy.layers.l2 import Ether, ARP
    from scapy.sendrecv import srp

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    if timeout:
        answers, _ = srp(packet, timeout=timeout, verbose=False)
    else:
        answers, _ = srp(packet, verbose=False)

    if answers:
        return answers[0][1][1].hwsrc
    else:
        return None


def callback(packet: Ether):
    """
    Callback for the sniff function.
    When it receives an "is-at" ARP packet, it will compare the ARP packet's MAC address with the MAC address that can
    be obtained using a "who-has".
    :param packet:
    :return:
    """
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # 2 = "is-at" mode
        ip_address = packet[ARP].psrc
        real_mac = get_mac(ip_address)
        if real_mac is None:
            # There was a timeout getting the MAC address
            return
        alleged_mac = packet[ARP].hwsrc
        if real_mac != alleged_mac:
            show_notification("WARNING",
                              f"{real_mac} is pretending to be {alleged_mac} at {ip_address}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-p",
                        "--passive",
                        action="store_true",
                        help="Performs a passive detection (does not require root)")
    parser.add_argument("-a",
                        "--active",
                        action="store_true",
                        help="Performs an active detection (requires root)")

    args = parser.parse_args()
    if not args.passive and not args.active:
        parser.print_help()
        exit(1)
    if args.passive and args.active:
        print("You cannot select both a passive and an active detection")
        exit(1)

    if args.passive:
        while True:
            devices = get_arp_cache()
            for i in range(len(devices)):
                for j in range(i + 1, len(devices)):
                    if devices[i].mac_address == devices[j].mac_address:
                        message = f"{devices[i].ip_address} has the same MAC address as {devices[j].ip_address}"
                        show_notification("WARNING", message)

            sleep(1)

    if args.active:
        check_root()
        sniff(store=False, prn=callback)
