import argparse
from ipaddress import IPv4Network
from os import getuid
from shutil import which
from subprocess import check_output
from threading import Thread
from time import sleep
from typing import Tuple, List

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sniff

from lan_scanner import Device
from notifications import NotificationManager


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


def get_arp_cache() -> List[Device]:
    """
    Fetch the system arp cache (supports ip neigh and arp -a)
    :return: a list of the cached_devices cached
    """
    cached_devices = []

    if which("ip") is not None:
        lines = check_output(("ip", "neigh")).decode().split('\n')
        for line in lines:
            fields = line.split()
            if len(fields) > 4:
                ip_address = fields[0]
                try:
                    IPv4Network(ip_address)
                except ValueError:
                    continue
                mac_address = fields[4]
                cached_devices.append(Device(ip_address, mac_address))
    elif which("arp") is not None:
        lines = check_output(("arp", "-a")).decode().split('\n')
        for line in lines:
            fields = line.split()
            if len(fields) > 3:
                ip_address = fields[1][1:-1]
                mac_address = fields[3]
                cached_devices.append(Device(ip_address, mac_address))

    return cached_devices


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
            spoof_detected_message = f"{alleged_mac_address} is pretending to be {real_mac_address} at {ip_address}"
            NotificationManager().show_notification("WARNING", spoof_detected_message)
    else:
        # Two or more devices (pretend they) have the same IP address
        duplicate_macs_message = f"All these devices think they have the IP address {ip_address}: {macs}"
        NotificationManager().show_notification("WARNING", duplicate_macs_message)


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
    parser.add_argument("-d",
                        "--delay",
                        type=float,
                        help="Don't show the same notification twice in less than <delay> seconds",
                        default=10)

    args = parser.parse_args()
    if not args.passive and not args.active:
        parser.print_help()
        exit(1)
    if args.passive and args.active:
        print("You cannot select both a passive and an active detection")
        exit(1)

    NotificationManager(args.delay)
    if args.active:
        if getuid() != 0:
            print("You have to run this script as root")
            exit(1)
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
                            NotificationManager().show_notification("WARNING", message)

                sleep(1)
        except KeyboardInterrupt:
            pass
