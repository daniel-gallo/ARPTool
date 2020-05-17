import argparse
from threading import Thread
from time import sleep
from typing import Tuple

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sniff

from mitm import get_arp_cache
from utils import check_root, show_notification


def get_macs(ip: str, timeout: int = None) -> Tuple:
    """
    Gets the MAC addresses of a given IP address
    :param ip: IP address
    :param timeout: if provided the function will wait timeout seconds, even if we already have a MAC address. If not,
    the function will terminate as soon as we have a MAC address.
    :return: a list of the MAC addresses of the devices that have that IP address
    """
    from scapy.layers.l2 import Ether, ARP
    from scapy.sendrecv import srp

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    if timeout is not None:
        answers, _ = srp(packet, multi=True, timeout=timeout, verbose=False)
    else:
        answers, _ = srp(packet, verbose=False)

    return tuple(set((answer[1][1].hwsrc for answer in answers)))


def verify(ip_address: str, alleged_mac_address: str):
    """
    Compares the ARP packet's MAC address with the MAC address that can be obtained using a "who-has".
    :param ip_address: ip_address of the "is-at" packet
    :param alleged_mac_address:  mac_address of the "is-at" packet
    """
    macs = get_macs(ip_address)

    if len(macs) == 0:
        # There was a timout getting the MAC address
        return
    elif len(macs) == 1:
        real_mac_address = macs[0]
        if real_mac_address != alleged_mac_address:
            show_notification("WARNING",
                              f"{alleged_mac_address} is pretending to be {real_mac_address} at {ip_address}")
    else:
        # Two or more devices (pretend they) have the same IP address
        show_notification("WARNING",
                          f"All these devices think they have the IP address {ip_address}: {macs}")


def callback(packet: Ether):
    """
    Callback for the sniff function.
    Verifies every "is-at" ARP packet on a separate thread
    :param packet
    """
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # 2 = "is-at" mode
        ip_address = packet[ARP].psrc
        alleged_mac = packet[ARP].hwsrc

        Thread(target=verify, args=(ip_address, alleged_mac)).start()


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

    if args.active:
        check_root()
        try:
            thread = Thread(target=sniff, kwargs={"store": False, "prn": callback}, daemon=True)
            thread.start()
            thread.join()
        except KeyboardInterrupt:
            pass
    elif args.passive:
        try:
            while True:
                devices = get_arp_cache()
                for i in range(len(devices)):
                    for j in range(i + 1, len(devices)):
                        if devices[i].mac_address == devices[j].mac_address:
                            message = f"{devices[i].ip_address} has the same MAC address as {devices[j].ip_address}"
                            show_notification("WARNING", message)

                sleep(1)
        except KeyboardInterrupt:
            pass
