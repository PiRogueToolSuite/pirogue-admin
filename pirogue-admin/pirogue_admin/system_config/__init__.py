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
import itertools
import json
import logging
import subprocess
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

import requests

from pirogue_admin.system_config.wireguard import WgManager


# This isn't a silver bullet but that logic worked well enough in the past:
DEFAULT_TARGET_IP = '1.1.1.1'

# Where to store systemd-networkd settings. That must be ordered before the
# default 10-netplan-all-{en,eth}.network (as shipped in Debian 12):
SYSTEMD_NETWORKD_CONF = '/etc/systemd/network/01-pirogue.network'


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
    # EXTERNAL_ADDRESS variable):
    return route_info[0]['dev']


def detect_network_stacks() -> list[NetworkStack]:
    """
    Check running systemd units, keeping in mind several stacks could be
    co-installed.
    """
    stacks = set()

    # Easy case: rely on activation case for some systemd units.
    if systemctl_is_active('systemd-networkd'):
        if systemctl_is_active('systemd-resolved'):
            stacks.add(NetworkStack.NETWORKD_RESOLVED)
        else:
            stacks.add(NetworkStack.NETWORKD)

    # Ditto:
    if systemctl_is_active('NetworkManager'):
        stacks.add(NetworkStack.NM)

    # Trickier, ifupdown.service is Type=oneshot and is unlikely to be disabled
    # when other units are active. Let's check whether configuration exists for
    # some interfaces. On the other hand, ifupdown might not even be installed,
    # so ifquery can trigger FileNotFoundError exception (caught via OSError).
    #
    # Try twice, because of auto interfaces (e.g. Pi images) vs. allow-hotplug
    # interfaces (e.g. d-i installations):
    for ifquery_args in (['--all'], ['--allow', 'hotplug']):
        try:
            ifquery = subprocess.check_output(['ifquery', '--list', *ifquery_args])
            # The loopback is returned systematically, even if /e/n/i is missing:
            interfaces = [x for x in ifquery.decode().splitlines() if x != 'lo']
            if interfaces:
                stacks.add(NetworkStack.IFUPDOWN)
        except (subprocess.CalledProcessError, OSError):
            pass

    # If we didn't find anything, record that fact:
    if not stacks:
        stacks.add(NetworkStack.UNKNOWN)

    # FIXME: Decide what to do whether there are too many things, either error
    # out frankly, or just return all detected stacks. For now, let's go the
    # easy way, return everything, and leave the decision to callers.
    return list(stacks)


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


def detect_external_ipv4_address(timeout: int = 30) -> ipaddress.IPv4Address:
    """
    Use icanhazip to determine a public IPv4 address.
    """
    try:
        reply = requests.get('http://ipv4.icanhazip.com/', timeout=timeout)
        reply.raise_for_status()
        # FIXME: Should we care about multiplicity? At least an empty string
        # would make IPv4Address() error out because it expects 4 bytes.
        return ipaddress.IPv4Address(reply.content.decode().rstrip())
    except BaseException as exception:
        raise RuntimeError(f'unable to detect public IPv4: {exception}')


def pick_isolated_network(external_networks) -> ipaddress.IPv4Network:
    """
    Given a list of external networks, find a network that doesn't conflict with
    any of them.

    PiRogue deployed on actual Raspberry Pi devices can manage less than a dozen
    devices, and a /24 seems plenty. Let's stick to this prefix length for the
    time being, that can be revisited if needed.

    RFC 1918 defines the following IP address ranges:
     - 10.0.0.0 – 10.255.255.255     = 10.0.0.0/8
     - 172.16.0.0 – 172.31.255.255   = 172.16.0.0/12
     - 192.168.0.0 – 192.168.255.255 = 192.168.0.0/16

    Let's for a systematic approach, iterating over all /24 subnets (ordering
    the historical 10.8.0.0/24 one first).
    """
    for net in itertools.chain([ipaddress.ip_network('10.8.0.0/24')],
                               ipaddress.ip_network('10.0.0.0/8').subnets(new_prefix=24),
                               ipaddress.ip_network('172.16.0.0/12').subnets(new_prefix=24),
                               ipaddress.ip_network('192.168.0.0/16').subnets(new_prefix=24)):
        candidate = True
        for external_net in external_networks:
            if net.overlaps(ipaddress.ip_network(external_net)):
                candidate = False
        if candidate:
            # There could be some doubt between IPv4Network and IPv6Network, but
            # given the parameters we pass, this is definitely IPv4Network here:
            return net  # type: ignore
    raise RuntimeError('unable to find a suitable network')


class SystemConfig:
    """
    System-level, pirogue-admin-specific configuration.

    We already have PackageConfig to manage package-provided index.yaml files
    documenting variables, files (templates), and actions.

    We also need to keep track of variables for pirogue-admin itself, which are
    very much tied to system-related discovery/auto-detection (the core of this
    module). Instead of trying to piggy-back onto the PackageConfig system,
    let's have a dedicated class dealing with the system configuration (mainly
    network-related settings, at least initially).

    The prefix can be used by PackageConfigLoader to ensure no clashes can
    happen with its PackageConfig instance.
    """
    PREFIX = 'SYSTEM_'

    def __init__(self):
        self.variables = [
            # This one is just for us and it must be resolvable using the
            # OperatingMode enum:
            f'{SystemConfig.PREFIX}OPERATING_MODE',
            # This one is tricky, we only require it if OPERATING is VPN:
            #   'PUBLIC_EXTERNAL_ADDRESS',
            # FIXME: There is some uncertainty in the appliance mode regarding
            # the interface for the isolated network (which might need being
            # configured as a DHCP client and/or without a DHCP server), but for
            # the time being, assume we do manage its configuration statically.
            'ISOLATED_NETWORK',
            'ISOLATED_ADDRESS',
            'ISOLATED_INTERFACE',
        ]
        self.stacks = detect_network_stacks()

    def apply_configuration(self, variables: dict[str, str]):
        """
        Apply the system configuration.

        In the PackageConfig case, we have a number of formatters that can error
        out if things aren't suitable. Let's implement our own checks.
        """
        logging.info('applying system configuration for pirogue-admin')
        requested_operating_mode = variables[f'{SystemConfig.PREFIX}OPERATING_MODE']
        try:
            operating_mode = OperatingMode(requested_operating_mode)
        except ValueError:
            raise RuntimeError(f'unknown operating mode: {requested_operating_mode}')

        if operating_mode in [OperatingMode.AP, OperatingMode.APPLIANCE]:
            logging.info('configuring the isolated interface')
            self.configure_isolated_interface(
                variables['ISOLATED_INTERFACE'],
                variables['ISOLATED_ADDRESS'],
                ipaddress.ip_network(variables['ISOLATED_NETWORK']).prefixlen
            )
        elif operating_mode in [OperatingMode.VPN]:
            # Tricky case: could we express that's a needed variable without
            # looking at the value of OPERATING_MODE?
            if 'PUBLIC_EXTERNAL_ADDRESS' not in variables:
                raise RuntimeError('missing variable (needed in VPN mode): '
                                   'PUBLIC_EXTERNAL_ADDRESS')

            # Instantiating the manager should be sufficient to get everything
            # configured (again):
            logging.info('configuring the wireguard stack')
            _manager = WgManager(
                variables['PUBLIC_EXTERNAL_ADDRESS'],
                variables['ISOLATED_ADDRESS'],
                variables['ISOLATED_NETWORK'],
            )
        else:
            raise NotImplementedError(f'support for {operating_mode} is missing at this point')

    def configure_isolated_interface(self, interface, address, prefixlen):
        """
        Configure the isolated interface.

        NOTE: If we're switching between interfaces, there's no way of knowing
        at this point. So we might need to have some explicit deconfiguration
        step if that needs to be supported.
        """
        if self.stacks == [NetworkStack.IFUPDOWN]:
            # For now, assume the snippets directory exists and is referenced in the
            # main /e/n/i file, even if we might want to add some checks to be extra
            # sure.
            interface_path = Path('/etc/network/interfaces.d') / interface
            interface_path.write_text(
                f'# Written by pirogue-admin:\n'
                f'auto {interface}\n'
                f'iface {interface} inet static\n'
                f'  address {address}/{prefixlen}\n'
            )

            # Declassify the file as it doesn't contain any secrets (Debian-provided
            # Raspberry Pi images have the wlan0 snippet restricted):
            interface_path.chmod(0o644)

            # Make sure the interface is configured right away, without relying on
            # ifupdown tools (ifdown's and ifup's internal state might make this
            # hard):
            subprocess.run(['ip', 'address', 'add', f'{address}/{prefixlen}', 'dev', interface],
                           check=False)

        elif self.stacks == [NetworkStack.NETWORKD_RESOLVED]:
            # FIXME: We could perform some introspection to see if and how the
            # interface is configured, but let's go for a direct configuration
            # for the time being.
            #
            # FIXME: We should perform some deconfiguration if we already had
            # a different interface in that file.
            Path(SYSTEMD_NETWORKD_CONF).write_text(
                f'# Written by pirogue-admin:\n'
                f'[Match]\n'
                f'Name={interface}\n'
                f'\n'
                f'[Network]\n'
                f'Address={address}/{prefixlen}\n'
            )

            # That seems to be sufficient, at least to configure an (otherwise)
            # unconfigured interface:
            subprocess.check_call(['networkctl', 'reload'])

        else:
            raise NotImplementedError(f'support for stacks={self.stacks} is missing at this point')

    def get_needed_variables(self) -> list[str]:
        """
        Return all required variables for this SystemConfig instance.

        See __init__()'s docstring for tricky variables.
        """
        return sorted(self.variables)


if __name__ == '__main__':
    import pprint
    print('Check running on Pi:')
    print(detect_raspberry_hardware())
    print()
    print('Detect network interfaces:')
    pprint.pprint(detect_network_interfaces())
    print()
    external_interface = detect_external_interface()
    print('Detect external interface:')
    pprint.pprint(external_interface)
    if external_interface:
        print()
        print('Detect external networks (external interface):')
        pprint.pprint(detect_ipv4_networks(external_interface))
    print()
    print('Detect external IPv4 address:')
    pprint.pprint(detect_external_ipv4_address())
    print()
    print('Detect network stacks:')
    pprint.pprint(detect_network_stacks())
    print()
    print('Suggest operating mode:')
    pprint.pprint(suggest_operating_mode())
