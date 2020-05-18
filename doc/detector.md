# Detector

In this program two approaches to detect ARP spoofing have been taken. Recall that this attack is done by continuously sending the victim ARP messages informing that the MAC address of the gateway is the attacker's. This changes the ARP cache of the victim and routes all their outgoing traffic through the attacker's machine.

## Passive detector

One way of detecting the attack is to find duplicates in the ARP cache table. This only works if the attacker was in the victim's ARP cache table. Fortunately for the victim, the attacker usually scans the network first (sending "who-has" ARP messages with their original IP and MAC addresses), so this detector is actually not that bad. Despite this, the attacker could easily circumvent this detector by waiting (staying radio silent, of course) until their ARP cache entry on the victim's computer expires. In addition, it doesn't require root access, since it only needs to run a simple command. ARPTool supports the traditional `arp -a` command (which works on most Linux distributions and on macOS) and the more modern `ip neigh`. 

## Active detector

This one is more sophisticated and the attacker cannot do anything to prevent its detection. It analyzes every "is-at" ARP message, checking that the provided MAC address matches the real one. Let's try to visualize this with an step-by-step example. Let's assume that the gateway IP and MAC addresses are 192.168.1.1 and ff:ff:ff:ff:ff:ff, respectevely. Let's assume too that the attacker's MAC address is 00:11:22:33:44:55.

1. The attacker sends us "192.168.1.1 is at 00:11:22:33:44:55"
2. We receive the message created by the attacker and create a new one: "Who has 192.168.1.1?"
3. The gateway will reply to our message saying "192.168.1.1 is at ff:ff:ff:ff:ff:ff". The attacker might also reply (although most MitM programs won't) with the fake message "192.168.1.1 is at 00:11:22:33:44:55"
4. When we receive the gateway message, we will know that the message the attacker sent was fake. If we receive two messages (one from the gateway and one from the attacker) we will also detect the attack. 

The only disadvantage of the active detector against the passive one is performance. In the active one, we must sniff all packages, filter the ARP ones, and verify each of them (sending a "who-has" ARP message). To improve speed, the verification part is done on a separate thread, so the sniffer is not blocked. 

## Notifications

On macOS, notifications will be sent natively. On Linux, the situation is more complicated, since the `notify-send` command doesn't work when run as sudo.

|                           | macOS               | Linux               |
| ------------------------- | ------------------- | ------------------- |
| Passive detector          | Native notification | Native notification |
| Active detector (as root) | Native notification | Command line print  |

## Conclusions

I have tested both detectors against several well-known tools. A summary table can be found below.

|           | Passive detector | Active detector |
| --------- | ---------------- | --------------- |
| ZANTI     | Yes              | Yes             |
| Bettercap | Yes              | Yes             |
| ARPTool   | Yes              | Yes             |

Both detectors seem to work reasonably good against typical ARP spoofing attacks. The active one will perform better on more complex scenarios, whereas the passive one has a lower impact on performance. The next step of this project will be to block malicious ARP messages and let the detector run in the background as a daemon.