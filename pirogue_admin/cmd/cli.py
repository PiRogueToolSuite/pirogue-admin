"""
Known limitations:
 - The focus is IPv4 connectivity, especially on the isolated network.
 - Permissions aren't considered in this early PoC, but we're going to write
   some secrets, so it might be good to have some concept of owner/group/mode
   for such files (instead of probably root/root/644 by default).
"""

import argparse

from pirogue_admin.package_config import PackageConfigLoader


ADMIN_CONFIG_DIR = '/usr/share/pirogue-admin'


def check_consistency():
    """
    Check consistency over all metadata files.

    This might mean checking default values for variables that are defined
    there, variables that are required, types of variables (which makes it
    possible to render them in various ways, e.g. DHCP range for dnsmasq,
    Grafana-regex matches, etc.), and more about actions and conditions.
    """
    loader = PackageConfigLoader(ADMIN_CONFIG_DIR)
    print(loader.configs)
    print(loader.get_needed_variables())
    print(loader.variables)
    needed = [x for x in loader.get_needed_variables() if x not in loader.variables]
    print(needed)


def autodetect_settings():
    """
    Use available interfaces to propose a best-guess setup.

    Make sure we have an interface connected to the internet (e.g. reusing the
    existing “route to 1.1.1.1” trick), fail otherwise.

    If that worked, try and find a wireless interface, and propose “access
    point” mode using it.

    If that didn't work, try and find another interface, and propose “appliance”
    mode using it.

    If that didn't work, propose “vpn” mode, which will eventually make another
    interface available.
    """
    raise NotImplementedError


def apply_configuration():
    """
    Deploy the selected configuration.

    Iterate over all metadata files, and deploy as needed.

    Over time components might want or need to declare some priority, so that
    they can be processed in the right order.
    """
    loader = PackageConfigLoader(ADMIN_CONFIG_DIR)
    # XXX: Maybe implement something to spot variables that are set but not used
    # anywhere (e.g. WIFI_NETWORK_NAME vs. WIFI_SSID)?
    loader.apply_configuration({
        'ISOLATED_NETWORK': '10.8.0.0/24',
        'ISOLATED_NETWORK_ADDR': '10.8.0.1',
        'ISOLATED_NETWORK_IFACE': 'enp1s0',
        'EXTERNAL_NETWORK_IFACE': 'enp2s0',
        'DASHBOARD_PASSWORD': 'miaou',
        'WIFI_SSID': 'PiRogue42',
    })


def main():
    """
    Entry point for the CLI.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true',
                        help='check consistency of all metadata files')
    parser.add_argument('--autodetect', action='store_true',
                        help='autodetect settings based on available interfaces')
    parser.add_argument('--apply', action='store_true',
                        help='apply the configuration')
    args = parser.parse_args()
    if args.check:
        check_consistency()
    if args.autodetect:
        autodetect_settings()
    if args.apply:
        apply_configuration()


if __name__ == '__main__':
    main()
