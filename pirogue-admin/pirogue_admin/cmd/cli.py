"""
Known limitations:
 - The focus is IPv4 connectivity, especially on the isolated network.
 - Permissions aren't considered in this early PoC, but we're going to write
   some secrets, so it might be good to have some concept of owner/group/mode
   for such files (instead of probably root/root/644 by default).
"""

import argparse
import logging
import os
import sys
from typing import TextIO

import yaml

from pirogue_admin.package_config import ConfigurationContext, PackageConfigLoader
from pirogue_admin.system_config import OperatingMode
from pirogue_admin.system_config import (detect_ipv4_networks,
                                         pick_isolated_network,
                                         suggest_operating_mode,)

WORKING_ROOT_DIR = '/'
ADMIN_CONFIG_DIR = '/usr/share/pirogue-admin'
ADMIN_VAR_DIR = '/var/lib/pirogue/admin'


def check_consistency(c_ctx: ConfigurationContext):
    """
    Check consistency over all metadata files.

    This might mean checking default values for variables that are defined
    there, variables that are required, types of variables (which makes it
    possible to render them in various ways, e.g. DHCP range for dnsmasq,
    Grafana-regex matches, etc.), and more about actions and conditions.
    """
    loader = PackageConfigLoader(c_ctx)
    logging.info(loader.system_config)
    logging.info(loader.configs)
    needed = [x for x in loader.get_needed_variables()
              if x not in loader.variables and x not in loader.current_config]

    pretty_print_map = {
        'needed_variables': loader.get_needed_variables(),
        'defaults': loader.variables,
        'remain_needed': needed,
        'currents': loader.current_config,
    }
    yaml.safe_dump(pretty_print_map, sys.stdout,
                   default_flow_style=False,
                   encoding="utf-8",
                   allow_unicode=True)


def autodetect_settings(c_ctx: ConfigurationContext):
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
    mode, external_interface, isolated_interfaces = suggest_operating_mode()

    # This is essential:
    if external_interface is None:
        logging.error('no external interface found, please check connectivity')
        sys.exit(1)

    # This is only temporary:
    if mode != OperatingMode.AP:
        logging.error('suggested mode is %s, not implemented yet!', mode)
        sys.exit(1)

    # Let's make sure we've got something to work with:
    if not isolated_interfaces:
        logging.error('no candidate interfaces for the isolated network')
        sys.exit(1)

    # Now arbitrarily focus on the first candidate interface. We might want to
    # make it possible to prompt here, to distinguish between interactive
    # detection (an admin can answer questions) and non-interactive detection
    # (initial installation might be non-interactive).
    isolated_interface = isolated_interfaces[0]
    logging.info('external: %s', external_interface)
    logging.info('isolated: %s', isolated_interface)

    # Now we need to find a suitable IP configuration for the isolated network,
    # taking the current configuration of the external interface into account.
    # We could ask the network stack with some introspection, but the quickest
    # might be to check `ip addr show`'s output. Note the plural.
    external_networks = detect_ipv4_networks(external_interface)
    logging.info('external networks: %s', external_networks)

    isolated_network = pick_isolated_network(external_networks)
    logging.info('isolated network picked: %s', isolated_network)

    # Finally pick the first address:
    isolated_address = next(isolated_network.hosts())
    logging.info('isolated address picked: %s', isolated_address)

    print(yaml.safe_dump({
        'ISOLATED_NETWORK': str(isolated_network),
        'ISOLATED_NETWORK_ADDR': str(isolated_address),
        'ISOLATED_NETWORK_IFACE': isolated_interface,
        'EXTERNAL_NETWORK_IFACE': external_interface,
        # This is for SystemConfig (pirogue-admin):
        'SYSTEM_OPERATING_MODE': mode.value,
    }))


def apply_configuration(c_ctx: ConfigurationContext, in_fd: TextIO):
    """
    Deploy the selected configuration.

    Iterate over all metadata files, and deploy as needed.

    Over time components might want or need to declare some priority, so that
    they can be processed in the right order.
    """
    if in_fd is None:
        in_fd = sys.stdin

    yml_style_config = yaml.safe_load(in_fd)

    logging.info('Applying: %s', yml_style_config)

    loader = PackageConfigLoader(c_ctx)
    loader.apply_configuration(yml_style_config)

    logging.info('Applied!')


def generate_definition_tree(c_ctx: ConfigurationContext, out_fd: TextIO):
    """
    Generates a configuration tree description of this pirogue instance.
    """
    loader = PackageConfigLoader(c_ctx)

    if out_fd is None:
        out_fd = sys.stdout

    whole_map = loader.get_configuration_tree()

    yaml.safe_dump(whole_map, out_fd,
                   sort_keys=False,
                   default_flow_style=False,
                   encoding="utf-8",
                   allow_unicode=True)

    if out_fd is not sys.stdout:
        out_fd.close()


def dump_current_configuration(c_ctx: ConfigurationContext, out_fd: TextIO):
    """

    """
    loader = PackageConfigLoader(c_ctx)

    if out_fd is None:
        out_fd = sys.stdout

    loader.dump_current_configuration(out_fd)

    if out_fd is not sys.stdout:
        out_fd.close()


def main():
    """
    Entry point for the CLI.
    """
    global ADMIN_CONFIG_DIR, ADMIN_VAR_DIR, WORKING_ROOT_DIR
    ADMIN_CONFIG_DIR = os.getenv('PIROGUE_ADMIN_CONFIG_DIR', ADMIN_CONFIG_DIR)
    ADMIN_VAR_DIR = os.getenv('PIROGUE_ADMIN_VAR_DIR', ADMIN_VAR_DIR)
    WORKING_ROOT_DIR = os.getenv('PIROGUE_WORKING_ROOT_DIR', WORKING_ROOT_DIR)

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true',
                        help='check consistency of all metadata files')
    parser.add_argument('--autodetect', action='store_true',
                        help='autodetect settings based on available interfaces')
    parser.add_argument('--from-scratch', action='store_true',
                        help='do not load existing configuration')
    parser.add_argument('--apply',
                        action='store', nargs='?', type=argparse.FileType('r'),
                        default=argparse.SUPPRESS,
                        help='''apply a new configuration to the system.
                        Configuration is read from an optional input file or stdin (default).
                        Configuration is a set of "KEY: 'value'" pairs''')
    parser.add_argument('--configuration-tree', '--tree', '-t',
                        action='store', nargs='?', type=argparse.FileType('w'),
                        default=argparse.SUPPRESS,
                        help='''generate a configuration tree map, describing this pirogue instance.
                        The descriptive tree is written to an optional file or stdout (default).''')
    parser.add_argument('--current-config', '--config',
                        action='store', nargs='?', type=argparse.FileType('w'),
                        default=argparse.SUPPRESS,
                        help='''dump out the current configuration used by this pirogue instance.
                        The current configuration is written to an optional file or stdout (default).
                        The current configuration is a set of "KEY: 'value'" pairs.''')
    parser.add_argument('--commit', action='store_true',
                        help='''disable dry-run mode and commit changes (writing system files and
                        executing hooks)''')

    args = parser.parse_args()

    c_ctx = ConfigurationContext(WORKING_ROOT_DIR, ADMIN_CONFIG_DIR, ADMIN_VAR_DIR,
                                 args.commit, args.from_scratch)

    if args.check:
        check_consistency(c_ctx)
    if args.autodetect:
        autodetect_settings(c_ctx)
    if 'apply' in args:
        apply_configuration(c_ctx, args.apply)
    if 'configuration_tree' in args:
        generate_definition_tree(c_ctx, args.configuration_tree)
    if 'current_config' in args:
        dump_current_configuration(c_ctx, args.current_config)


if __name__ == '__main__':
    main()