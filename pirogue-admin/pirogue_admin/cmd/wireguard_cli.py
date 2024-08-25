"""
WireGuard admin CLI.

This is mainly to make sure the WgManager class is implemented correctly before
it's exposed through the gRPC interface, and is usable remotely and locally via
a dedicated pirogue-admin client.

Until that happens, this CLI can be used to manage peers when pirogue-admin is
set to the VPN operating mode: some variables are read from pirogue-admin's main
config.yaml file, using fallback values if the file is missing or doesn't
contain the required variables.
"""

import argparse
import logging
from pathlib import Path

import yaml

from pirogue_admin.system_config.wireguard import WgManager
from pirogue_admin.system_config import detect_external_ipv4_address
from pirogue_admin.cmd.cli import ADMIN_VAR_DIR


def main():
    """
    Entry point for the WireGuard CLI.
    """
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    # Manipulate peer(s), with the Python representation:
    parser.add_argument('--add', type=str)
    parser.add_argument('--delete', type=int)
    parser.add_argument('--get', type=int)
    parser.add_argument('--list', action='store_true')
    # Generate request peer configuration files:
    parser.add_argument('--generate-conf', type=int)
    parser.add_argument('--generate-zip', type=int)
    parser.add_argument('--generate-qrcode', type=int)
    args = parser.parse_args()

    # Set fallback values in case pirogue-admin's config.yaml file is missing or
    # doesn't contain the expected variables:
    public_external_address = detect_external_ipv4_address()
    isolated_address = '10.8.0.1'
    isolated_network = '10.8.0.0/24'

    # Read variables from pirogue-admin's config.yaml file (manually):
    config_path = Path(ADMIN_VAR_DIR) / 'config.yaml'
    if config_path.exists():
        try:
            config = yaml.safe_load(config_path.read_text())
            if 'PUBLIC_EXTERNAL_ADDRESS' in config:
                public_external_address = config['PUBLIC_EXTERNAL_ADDRESS']
            if 'ISOLATED_ADDRESS' in config:
                isolated_address = config['ISOLATED_ADDRESS']
            if 'ISOLATED_NETWORK' in config:
                isolated_network = config['ISOLATED_NETWORK']
        except BaseException:
            pass

    # Use strings all the time, making things easier with serialization to and
    # deserialization from the yaml config file used by the WireGuard manager:
    manager = WgManager(
        public_external_address,
        isolated_address,
        isolated_network,
    )

    # In all cases below, echo the returned object:
    if args.add:
        # Support both "this-is-a-comment,public-key==" and "this-is-a-comment"
        # (as well as "," to generate both the comment and the key pair):
        if args.add.find(',') != -1:
            # FIXME: Decide on a comment format, then validate it.
            comment, public_key = args.add.split(',')[0:2]
            print(manager.add(comment, public_key))
        else:
            # FIXME: Decide on a comment format, then validate it.
            print(manager.add(args.add, ''))
    if args.delete:
        print(manager.delete(args.delete))
    if args.get:
        print(manager.get(args.get))
    if args.list:
        print(manager.list())

    # In all cases below, generate a WireGuard peer configuration file:
    def generate_args(arg, extension):
        # Maybe include the pattern in help strings:
        config_pattern = 'PiRogue-peer-%d.%s'
        return arg, Path(config_pattern % (arg, extension))
    if args.generate_conf:
        manager.generate_conf(*generate_args(args.generate_conf, 'conf'))
    if args.generate_zip:
        manager.generate_zip(*generate_args(args.generate_zip, 'zip'))
    if args.generate_qrcode:
        manager.generate_qrcode(*generate_args(args.generate_qrcode, 'png'))


if __name__ == '__main__':
    main()
