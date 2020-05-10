import curses
from ipaddress import IPv4Network
from threading import Thread, Lock
from typing import Optional, List, Dict

import netifaces
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr

from discoverer import discoverer, Device
from mitm import Poisoner, is_ip_forwarding_enabled, enable_ip_forwarding, disable_ip_forwarding


class Interface:
    SELECTED_COLOR_SCHEME = 1
    IP_FORWARDING_ENABLED_COLOR_SCHEME = 2
    IP_FORWARDING_DISABLED_COLOR_SCHEME = 3

    def __init__(self):
        self.devices: List[Device] = []
        self.selected_device: Optional[Device] = None
        self.gateway: Optional[Device] = None
        self.poisoning: Dict[Device, Poisoner] = {}
        self.mutex = Lock()
        # Launch the main screen
        self.stdscr = None
        curses.wrapper(self.main)
        # Stop threads to restore the ARP tables
        for poisoner in self.poisoning.values():
            poisoner.stop()
        for poisoner in self.poisoning.values():
            poisoner.stop_and_join()

    def print_center(self, text: str):
        with self.mutex:
            self.stdscr.clear()
            heigth, width = self.stdscr.getmaxyx()
            x = width // 2 - len(text) // 2
            y = heigth // 2
            self.stdscr.addstr(y, x, text)
            self.stdscr.refresh()

    def print_menu(self):
        with self.mutex:
            self.stdscr.clear()
            # Get terminal size
            heigth, width = self.stdscr.getmaxyx()
            # Select the first device is none was selected and there are devices discovered
            if self.selected_device is None and self.devices:
                self.selected_device = self.devices[0]
            self.stdscr.addstr(0, 1, "Hakd\tIP Address\tMAC Address\t\tManufacturer", curses.A_BOLD)
            for i, device in enumerate(self.devices):
                # TODO: Trim text so it doesn't overflow the screen
                if self.gateway and self.gateway == device:
                    text = "[G]\t"
                else:
                    text = "[#]\t" if device in self.poisoning else "[ ]\t"
                text += str(device)
                text = text[:width - 10]
                # x = width // 2 - len(row) // 2
                # y = heigth // 2 - len(self.devices) // 2 + i
                x = 1
                y = i + 1
                if device == self.selected_device:
                    self.stdscr.attron(curses.color_pair(Interface.SELECTED_COLOR_SCHEME))
                    self.stdscr.addstr(y, x, text)
                    self.stdscr.attroff(curses.color_pair(Interface.SELECTED_COLOR_SCHEME))
                else:
                    self.stdscr.addstr(y, x, text)

            if is_ip_forwarding_enabled():
                self.stdscr.attron(curses.color_pair(Interface.IP_FORWARDING_ENABLED_COLOR_SCHEME))
                self.stdscr.addstr(len(self.devices) + 1, 1, "IP Forwarding enabled")
                self.stdscr.attroff(curses.color_pair(Interface.IP_FORWARDING_ENABLED_COLOR_SCHEME))
            else:
                self.stdscr.attron(curses.color_pair(Interface.IP_FORWARDING_DISABLED_COLOR_SCHEME))
                self.stdscr.addstr(len(self.devices) + 1, 1, "IP Forwarding disabled")
                self.stdscr.attroff(curses.color_pair(Interface.IP_FORWARDING_DISABLED_COLOR_SCHEME))

        self.stdscr.refresh()

    def main(self, stdscr):
        # Save stdscr into class for convenience
        self.stdscr = stdscr
        # Turn off cursor blinking
        curses.curs_set(0)
        # Initialize color schemes
        curses.init_pair(Interface.SELECTED_COLOR_SCHEME, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(Interface.IP_FORWARDING_ENABLED_COLOR_SCHEME, curses.COLOR_BLACK, curses.COLOR_GREEN)
        curses.init_pair(Interface.IP_FORWARDING_DISABLED_COLOR_SCHEME, curses.COLOR_BLACK, curses.COLOR_RED)

        # Print a temporary message while the network is explored
        self.print_center("Scanning network...")

        # Get gateway information
        gateway_ip, iface = netifaces.gateways()["default"][netifaces.AF_INET]
        netmask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]["netmask"]
        mask_bits = IPv4Network(f"0.0.0.0/{netmask}").prefixlen
        cidr = f"{gateway_ip}/{mask_bits}"
        ans, _ = sr(ARP(op="who-has", pdst=gateway_ip), verbose=False)
        gateway_mac = ans[0][1].hwsrc
        self.gateway = Device(ip_address=gateway_ip, mac_address=gateway_mac)
        # Launch the discoverer thread
        Thread(target=discoverer,
               args=(cidr, self.devices, self.mutex, self.print_menu, 1),
               daemon=True).start()

        try:
            while True:
                key = stdscr.getch()

                with self.mutex:
                    if len(self.devices) == 0:
                        # There's no devices to select
                        continue
                    elif self.selected_device is None:
                        self.selected_device = self.devices[0]

                    if key == curses.KEY_DOWN:
                        index = self.devices.index(self.selected_device)
                        if index < len(self.devices) - 1:
                            self.selected_device = self.devices[index + 1]
                    elif key == curses.KEY_UP:
                        index = self.devices.index(self.selected_device)
                        if index > 0:
                            self.selected_device = self.devices[index - 1]
                    elif key in (curses.KEY_ENTER, ord('\n'), ord(' ')):
                        if self.selected_device in self.poisoning:
                            self.poisoning[self.selected_device].stop_and_join()
                            del self.poisoning[self.selected_device]
                        elif self.selected_device != self.gateway:
                            self.poisoning[self.selected_device] = Poisoner(gateway_ip=gateway_ip,
                                                                            gateway_mac=gateway_mac,
                                                                            target_ip=self.selected_device.ip_address,
                                                                            target_mac=self.selected_device.mac_address)
                    elif key == ord('\t'):
                        if is_ip_forwarding_enabled():
                            disable_ip_forwarding()
                        else:
                            enable_ip_forwarding()
                    else:
                        continue

                self.print_menu()
        except KeyboardInterrupt:
            return


Interface()
