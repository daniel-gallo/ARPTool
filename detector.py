from time import sleep

from mitm import get_arp_cache
from lan_scanner import get_devices
from utils import get_gateway_information, show_notification

cached_devices = get_arp_cache()

gateway_ip, gateway_mac, netmask = get_gateway_information()

while True:
    cached_devices = get_arp_cache()
    scanned_devices = get_devices(netmask, 1)

    for scanned_device in scanned_devices:
        for cached_device in cached_devices:
            if cached_device.mac_address == scanned_device.mac_address and \
                    cached_device.ip_address != scanned_device.ip_address:
                show_notification("WARNING",
                                  f"{scanned_device.ip_address} has the same MAC address than {cached_device.ip_address}")

    sleep(1)
