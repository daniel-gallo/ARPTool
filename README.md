# ARPTool
ARPTool is my project for UAM's *Communication Networks II* course. It has two main programs, both written in Python 3.6+.
## Attacker
It provides a nice CLI to see the devices on the LAN and perform ARP spoofing attacks on them.

```bash
sudo python attacker.py
```

![](/home/daniel/PycharmProjects/ARPTool/doc/attacker.png)

To ARP spoof a device just select it using the arrows and press `Enter` or `Space`.  An asterisk indicates whether a device is being spoofed or not. IP Forwarding can be enabled or disabled pressing `Tab`. Spoofed devices won't have Internet access unless IP Forwarding is enabled. To quit, press `q` or `Control+C`.

## Detector

Two detectors have been implemented.

### Passive detector

It works detecting duplicates on the ARP cache (using ```ip neigh``` or  ```arp -a```). It's not the most effective detector because the victim might not have the attacker's MAC address on their ARP cache. It does not require root permission

```bash
python detector.py --passive
```

### Active detector

Every ARP *is-at* message received will be analyzed. For instance if "192.168.1.1 is at 00:11:22:33:44:55" is received, a "Who has 192.168.1.1?" message will be sent to the broadcast address. If we get a different MAC address than 00:11:22:33:44:55 an ARP spoofing attack is probably happening.

```bash
sudo python detector.py --active
```



