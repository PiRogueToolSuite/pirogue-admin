"""
This module deals with system configuration.

It implements:

 - detecting whether a route to the internet exists, and which interface is
   uses;
 - detecting available network interfaces and their types;
 - detecting which network management stack is in used (e.g. ifupdown vs.
   systemd-network/systemd-resolved);
 - suggesting the right mode based on what is detected.
"""

import ipaddress
import json
import logging
import subprocess
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple


# This isn't a silver bullet but that logic worked well enough in the past:
DEFAULT_TARGET_IP = '1.1.1.1'


class DevType(Enum):
    """
    Device types for interfaces.
    """
    ETHERNET = 'eth'
    WIRELESS = 'wlan'
    WIREGUARD = 'wireguard'
    UNKNOWN = '???'


class NetworkStack(Enum):
    """
    Network management stack.

    The following options could be combined in some ways, but we definitely
    shouldn't try and accommodate each and every combination. Instead, warning
    against mixing and matching should do the trick.

    The following doesn't account for netplan which supports several backends.
    At least systemd-networkd can be configured by dropping a file under
    /etc/systemd/network so hopefully we shouldn't have to care about it.
    """
    # Default on Pi images provided by Debian:
    IFUPDOWN = 'ifupdown'
    # Not recommended (systemd's README.Debian recommends using both together):
    NETWORKD = 'systemd-networkd without systemd-resolved'
    # Default on cloud images provided by Debian:
    NETWORKD_RESOLVED= 'systemd-networkd with systemd-resolved'
    # That would be pulled by desktop environments, which might happen in the
    # “appliance mode using a laptop” case:
    NM = 'NetworkManager'
    # If none of the above applies:
    UNKNOWN = '???'


def detect_network_interfaces() -> dict[str, DevType]:
    """
    TODO: Define which interfaces we are comfortable enough to try and
    configure.

    For example, we might want to exclude anything that resembles a virtual
    interface, like a bridge.
    """
    # Start by excluding the loopback:
    interfaces = {}
    for net_dir in sorted(Path('/sys/class/net/').glob('*')):
        if net_dir.name == 'lo':
            continue

        # Unless we know better, an interface is Ethernet-like:
        devtype = DevType.ETHERNET

        # Surely one of wireless flag file vs. DEVTYPE=wlan is enough. And since
        # we might want to exclude things based on DEVTYPE, let's concentrate on
        # that? Otherwise, condition on: (net_dir / 'wireless').exists()
        uevent = net_dir / 'uevent'
        if uevent.exists():
            lines = uevent.read_text().splitlines()

            # KISS: focus on regular interfaces for the time being. We can
            # always try and support bridges when users start asking for it.
            if 'DEVTYPE=bridge' in lines:
                continue

            # The first two we know about and are happy to deal with, other
            # values we flag as unknown:
            if 'DEVTYPE=wlan' in lines:
                devtype = DevType.WIRELESS
            elif 'DEVTYPE=wireguard' in lines:
                devtype = DevType.WIREGUARD
            else:
                for line in lines:
                    if line.startswith('DEVTYPE='):
                        devtype = DevType.UNKNOWN
        interfaces[net_dir.name] = devtype
    return interfaces


def detect_external_interface(target_ip: str = DEFAULT_TARGET_IP) -> Optional[str]:
    """
    Use routing information to see whether internet seems reachable.
    """
    ip_route = subprocess.run(['ip', '--json', 'route', 'get', target_ip],
                              capture_output=True, check=False)
    if ip_route.returncode != 0:
        return None

    # Let any explosions there bubble up:
    route_info = json.loads(ip_route.stdout.decode())

    # This seems unlikely, but let's fail gracefully if that happens:
    if len(route_info) == 0:
        return None

    # For systems with multiple default routes it seems the metric is used to
    # determine a single interface, leading to an array with a single element
    # even with Ethernet + wireless. It doesn't seem to be possible to have the
    # same metric anyway.
    if len(route_info) > 1:
        # Maybe log a warning? Then move on to picking the first entry?
        pass

    # If we are curious, we have more information in there, including the
    # gateway's IP and our own source IP (in case we need to introduce an
    # EXTERNAL_NETWORK_ADDR variable):
    return route_info[0]['dev']


def detect_network_stacks() -> list[NetworkStack]:
    """
    Check running systemd units, keeping in mind several stacks could be
    co-installed.
    """
    stacks = []

    # Easy case: rely on activation case for some systemd units.
    if systemctl_is_active('systemd-networkd'):
        if systemctl_is_active('systemd-resolved'):
            stacks.append(NetworkStack.NETWORKD_RESOLVED)
        else:
            stacks.append(NetworkStack.NETWORKD)

    # Ditto:
    if systemctl_is_active('NetworkManager'):
        stacks.append(NetworkStack.NM)

    # Trickier, ifupdown.service is Type=oneshot and is unlikely to be disabled
    # when other units are active. Let's check whether configuration exists for
    # some interfaces. On the other hand, ifupdown might not even be installed,
    # so ifquery can trigger FileNotFoundError exception (caught via OSError).
    try:
        ifquery = subprocess.check_output(['ifquery', '--list', '--all'])
        # The loopback is returned systematically, even if /e/n/i is missing:
        interfaces = [x for x in ifquery.decode().splitlines() if x != 'lo']
        if interfaces:
            stacks.append(NetworkStack.IFUPDOWN)
    except (subprocess.CalledProcessError, OSError):
        pass

    # If we didn't find anything, record that fact:
    if not stacks:
        stacks.append(NetworkStack.UNKNOWN)

    # FIXME: Decide what to do whether there are too many things, either error
    # out frankly, or just return all detected stacks. For now, let's go the
    # easy way, return everything, and leave the decision to callers.
    return stacks


def systemctl_is_active(unit: str) -> bool:
    """
    Helper for the above function.
    """
    return subprocess.run(['systemctl', '-q', 'is-active', unit], check=False).returncode == 0


class OperatingMode(Enum):
    """
    Three modes have been defined to cover many use cases.

    The initial best guess implementation considers them in turn, and recommends
    the first that fits:
      - access point is the historical behaviour on Raspberry Pi, with wlan0 for
        the isolated network and eth0 for the external network (wireless→wired).
      - appliance covers a wide range of use cases (including baremetal servers
        and dedicated VMs), with two Ethernet interfaces (wired→wired).
      - vpn is the fallback if a single interface is spotted, and setting up
        wireguard is going to make a new interface pop up to manage the isolated
        network (vpn→wired).
    """
    AP = 'access point'
    APPLIANCE = 'appliance'
    VPN = 'wireguard'
    UNKNOWN = '???'


def suggest_operating_mode() -> Tuple[OperatingMode, Optional[str], List[str]]:
    """
    Implement a best guess based on available interfaces.

    We probably should do something about unknown interfaces, but surely the
    caller can warn about them, so that users can inform us about the weird
    things they might want us to support.

    At the moment, this doesn't taken into account whether interfaces were
    configured already (by pirogue-admin or someone else).

    Return a mode, the name of the external interface (might be None if we are
    really unlucky), and a list of candidate interfaces for the isolated
    network.
    """
    # Better be connected already!
    external = detect_external_interface()
    if external is None:
        return (OperatingMode.UNKNOWN,
                None,
                [])

    # Let's assume we never want to touch the external interface (be it wired,
    # wireless, or something else). Also, it might not show up in weird cases
    # (e.g. it's a bridge, which we exclude deliberately:
    interfaces = detect_network_interfaces()
    if external in interfaces:
        del interfaces[external]

    # 1st attempt is AP mode:
    wireless_interfaces = sorted([iface for iface, devtype in interfaces.items()
                                  if devtype == DevType.WIRELESS])
    if wireless_interfaces:
        return (OperatingMode.AP,
                external,
                wireless_interfaces)

    # 2nd attempt is appliance mode:
    ethernet_interfaces = sorted([iface for iface, devtype in interfaces.items()
                                  if devtype == DevType.ETHERNET])
    if ethernet_interfaces:
        return (OperatingMode.APPLIANCE,
                external,
                ethernet_interfaces)

    # Fallback is vpn mode, we mention possible wireguard interfaces for
    # information, but see this function's docstring.
    wireguard_interfaces = sorted([iface for iface, devtype in interfaces.items()
                                   if devtype == DevType.WIREGUARD])
    return (OperatingMode.VPN,
            external,
            wireguard_interfaces)


def detect_raspberry_hardware() -> bool:
    """
    Check if running on a supported Raspberry Pi device (3B, 3B+, 4B, or 5B).

    The PiRogue environment was initially developed for Pi 3 and Pi 4, and we
    want to make extra sure the initial configuration is still trivial there,
    so we have specific detection code for Raspberry Pi devices.
    """
    compatible_path = Path('/proc/device-tree/compatible')
    if not compatible_path.exists():
        return False

    compatible_text = compatible_path.read_text()
    models = [
        'raspberrypi,3-model-b-plus\x00brcm,bcm2837\x00',
        'raspberrypi,3-model-b\x00brcm,bcm2837\x00',
        'raspberrypi,4-model-b\x00brcm,bcm2711\x00',
        'raspberrypi,5-model-b\x00brcm,bcm2712\x00',
    ]
    if compatible_text in models:
        return True
    return False


def detect_ipv4_networks(interface: str) -> List[str]:
    """
    Return a list of CIDR networks for the specified interface.

    We would usually expect a single network, but non-trivial setups might
    involved having several IP addresses on a single interface. And we want to
    use that information to pick non-conflicting settings for the isolated
    network.
    """
    try:
        networks = set()
        ip_json = subprocess.check_output([
            'ip', '--json', 'addr', 'show', 'dev', interface
        ]).decode()
        ip_output = json.loads(ip_json)
        # We expect a single interface here as we used "dev interface":
        for interface_info in ip_output:
            # But we might have several addr_info:
            for addr_info in interface_info['addr_info']:
                if addr_info['family'] != 'inet':
                    continue
                # Get the network out of the address plus prefix information,
                # turning off strict mode since host bits are set:
                network = ipaddress.IPv4Network(f'{addr_info["local"]}/{addr_info["prefixlen"]}',
                                                strict=False)
                logging.info('spotting network: %s', network)
                networks.add(str(network))
        return sorted(networks)
    except BaseException as exception:
        raise RuntimeError(f'unable to detect IPv4 networks: {exception}')


if __name__ == '__main__':
    import pprint
    print('Check running on Pi:')
    print(detect_raspberry_hardware())
    print()
    print('Detect network interfaces:')
    pprint.pprint(detect_network_interfaces())
    print()
    print('Detect external interface:')
    pprint.pprint(detect_external_interface())
    print()
    print('Detect network stack:')
    pprint.pprint(detect_network_stacks())
    print()
    print('Suggest operating mode:')
    pprint.pprint(suggest_operating_mode())
