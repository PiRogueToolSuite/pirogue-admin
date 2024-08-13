"""
Known limitations:
 - The focus is IPv4 connectivity, especially on the isolated network.
 - Permissions aren't considered in this early PoC, but we're going to write
   some secrets, so it might be good to have some concept of owner/group/mode
   for such files (instead of probably root/root/644 by default).
"""

import argparse
import os
import sys
from typing import TextIO

import yaml

from pirogue_admin.package_config import ConfigurationContext, PackageConfigLoader

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
    print(loader.configs)
    #print(loader.get_needed_variables())
    #print(loader.variables)
    needed = [x for x in loader.get_needed_variables()
              if x not in loader.variables and x not in loader.current_config]
    #print(needed)

    pretty_print_map = {
        #'configs': loader.configs,
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
    raise NotImplementedError


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

    print('Applying:', yml_style_config)

    loader = PackageConfigLoader(c_ctx)
    # XXX: Maybe implement something to spot variables that are set but not used
    # anywhere (e.g. WIFI_NETWORK_NAME vs. WIFI_SSID)
    # loader.apply_configuration({
    #    'ISOLATED_NETWORK': '10.8.0.0/24',
    #    'ISOLATED_NETWORK_ADDR': '10.8.0.1',
    #    'ISOLATED_NETWORK_IFACE': 'enp1s0',
    #    'EXTERNAL_NETWORK_IFACE': 'enp2s0',
    #    'DASHBOARD_PASSWORD': 'miaou',
    #    'WIFI_SSID': 'PiRogue42',
    # })

    loader.apply_configuration(yml_style_config)


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
