"""
This module deals with WireGuard configuration.

For the time being, it's restricted to IPv4 given constraints elsewhere, but it
should be easy to support both IPv4 and IPv6.
"""

import base64
import binascii
import ipaddress
import logging
import re
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from subprocess import check_call, check_output, run, DEVNULL
from typing import List, Optional, Tuple

import yaml

from pirogue_admin.tools import get_size_and_digest


WG_ETC_DIR = '/etc/wireguard'
WG_VAR_DIR = '/var/lib/pirogue/admin/wireguard'
DEFAULT_WG_IFACE = 'wg0'
DEFAULT_WG_PORT = 51820

# FIXME: Do we want this value (picked from https://wiki.debian.org/WireGuard),
# something else, or do we want to use whatever the default is?
DEFAULT_WG_PERSISTENT_KEEP_ALIVE = 20

# This seems to directly impact the size of the generated PNG, e.g. 650×650
# instead of 195×195 with the default size (3):
QRENCODE_DOT_SIZE = 10


@dataclass
class WgPeer:
    """
    WireGuard peer (or “client”).

    FIXME: If it makes sense to keep the “comment” concept, we should define
    a format and enforce it. Then we can think of maybe including it in
    a comment when the peer config is generated, for informational purposes.
    """
    idx: int
    comment: str
    private_key: str
    public_key: str

    def get_ipv4_address(self, network: str):
        """
        Build the IP address within the specified network.
        """
        # IPv4/IPv6:
        network_bytes = network.split('.')[0:3]
        return f'{".".join(network_bytes)}.{self.idx}'


@dataclass
class WgConfig:  # pylint: disable=too-many-instance-attributes
    """
    WireGuard config, dealing with “server”-side settings as well as keeping
    track of the various peers.

    A number of parameters can be tweaked between runs, some of them coming with
    default values (interface name, listening port), but some other things are
    kept in the config file: peers and private/public key pair.
    """
    public_external_address: str
    isolated_address: str
    isolated_network: str
    isolated_interface: str
    port: int
    # `field(…)` is used instead of `= []` or `= ''` to set default values:
    private_key: str = field(default_factory=str)
    public_key: str = field(default_factory=str)
    peers: List[WgPeer] = field(default_factory=list)

    def __post_init__(self):
        """
        A WgConfig instance is created from WgManager.__init__() without any
        peers, or from WgManager.save_config() when it's called with merge=True.
        In the latter case, existing peers are just dicts (read back from the
        config file), which need to be turned back into proper WgPeer instances.
        """
        actual_peers = []
        for peer in self.peers:
            # Just for the peace of mind:
            if not isinstance(peer, WgPeer):
                actual_peers.append(WgPeer(**peer))
        self.peers = actual_peers


class WgManager:
    """
    WireGuard manager, tracking the overall WireGuard config for the PiRogue,
    the WireGuard (server-side) interface config and associated systemd unit,
    and everything peer-related.

    While it's possible to add peers with their public key, it's probably a
    better idea to let pirogue-admin deal with generating the key pair: it can
    generate config file, config archive, and config QR code in that case.
    """
    # IPv4/IPv6:
    PREFIXLEN = 24

    # Format string for generate_*() methods:
    PEER_CONFIG_FORMAT = 'PiRogue-peer-%(idx)d.%(extension)s'

    def __init__(self,  # pylint: disable=too-many-arguments
                 public_external_address: str,
                 isolated_address: str,
                 isolated_network: str,
                 isolated_interface: str = DEFAULT_WG_IFACE,
                 port: int = DEFAULT_WG_PORT,
                 ):
        """
        Initialize or update server-side settings.
        """
        # IPv4/IPv6: we make some assumptions in the code, e.g. using the index
        # for the fourth byte.
        prefixlen = ipaddress.IPv4Network(isolated_network).prefixlen
        if prefixlen != WgManager.PREFIXLEN:
            raise RuntimeError(f'unexpected prefix length {prefixlen} '
                               f'(expected={WgManager.PREFIXLEN})')

        self.config = WgConfig(
            public_external_address,
            isolated_address,
            isolated_network,
            isolated_interface,
            port
        )

        # If a config file exists, peer information is merged from there:
        self.save_config(merge=True)
        self.deploy_config()

    def add(self, comment: str, public_key: str) -> WgPeer:
        """
        API call: add a peer.

        At least initially we don't let the caller pick the ID because they
        would have to figure out what's available, what's not, and they
        shouldn't have to care about our implementation.
        """
        if not WgManager.validate_comment_format(comment):
            raise ValueError(f'invalid peer comment (format check failed): {comment}')

        # Compute an index, and make sure to have a comment:
        idx = self.get_free_index()

        # If we get a public_key, we store an empty private_key; otherwise we
        # have to generate a private/public key pair on the fly.
        to_add = None
        if public_key != '':
            # Minimal check, we don't want to store junk silently:
            try:
                assert public_key.isascii()
                base64.b64decode(public_key, validate=True)
            except (AssertionError, binascii.Error):
                # Which exception got triggered doesn't matter:
                raise RuntimeError('public key cannot be base64-decoded') from None
            to_add = WgPeer(idx, comment, "", public_key)
        else:
            to_add = WgPeer(idx, comment, *self.generate_key_pair())

        self.config.peers.append(to_add)
        self.save_config(merge=False)
        self.deploy_config()
        return to_add

    def delete(self, idx: int) -> WgPeer:
        """
        API call: delete a peer, by index.
        """
        new_peers = []
        to_delete = None
        for peer in self.config.peers:
            if peer.idx != idx:
                new_peers.append(peer)
            else:
                to_delete = peer

        if to_delete is None:
            raise RuntimeError(f'no peer with index={idx}')

        self.config.peers = new_peers
        self.save_config(merge=False)
        self.deploy_config()
        return to_delete

    def get(self, idx: int) -> WgPeer:
        """
        API call: get a peer, by index.
        """
        for peer in self.config.peers:
            if peer.idx == idx:
                return peer
        raise RuntimeError(f'no peer with index={idx}')

    def list(self) -> List[WgPeer]:
        """
        API call: list all peers (== get them all).
        """
        return self.config.peers

    def generate_conf(self, idx: int, opt_dest: Optional[Path]):
        """
        API call: generate the peer config file.
        """
        dest = self.select_destination(idx, opt_dest, 'conf')
        with dest.with_suffix('.new') as new_dest:
            new_dest.touch(0o600)
            new_dest.write_text(self.get_peer_config(idx))
            new_dest.rename(dest)
        logging.info('generated conf: %s', dest)
        return dest

    def generate_zip(self, idx: int, opt_dest: Optional[Path]):
        """
        API call: generate the peer config file, wrapped in a zip.

        Use the name of the destination file, with '.zip' replaced by '.conf',
        for the included config file.
        """
        dest = self.select_destination(idx, opt_dest, 'zip')
        with dest.with_suffix('.new') as new_dest:
            new_dest.touch(0o600)
            with zipfile.ZipFile(new_dest, mode="w") as archive:
                archive.writestr(dest.name.replace('.zip', '.conf'),
                                 self.get_peer_config(idx))
            new_dest.rename(dest)
        logging.info('generated zip: %s', dest)
        return dest

    def generate_qrcode(self, idx: int, opt_dest: Optional[Path]):
        """
        API call: generate the peer config file, as a QR code.

        Python bindings exist, but were last released in 2016, and are quite
        limited. Let's use the CLI directly!

        We could support different formats, but the SVG output looks weird
        compared to the PNG one, with a slight gap between each pixel.

        There are two PNG formats:
         - PNG means 1-bit colormap, non-interlaced
         - PNG32 means 8-bit/color RGBA, non-interlaced

        Let's focus on PNG (which is the default, and slightly smaller) for the
        time being.
        """
        dest = self.select_destination(idx, opt_dest, 'png')
        with dest.with_suffix('.new') as new_dest:
            new_dest.touch(0o600)
            qrcode = check_output(
                ['qrencode', '-t', 'PNG', '-s', str(QRENCODE_DOT_SIZE), '-o', '-'],
                input=self.get_peer_config(idx).encode('utf-8')
            )
            new_dest.write_bytes(qrcode)
            new_dest.rename(dest)
        logging.info('generated qrcode: %s', dest)
        return dest

    def generate_key_pair(self) -> Tuple[str, str]:
        """
        Use wg command to generate a (private, public) tuple.

        wg(8) documents: wg genkey | tee privatekey | wg pubkey > publickey
        """
        private = check_output(['wg', 'genkey'])
        public = check_output(['wg', 'pubkey'], input=private)
        return private.decode().rstrip(), public.decode().rstrip()

    def get_free_index(self):
        """
        Iterate over all addresses in the network, excluding our own
        address, get the last byte, and excluding all known indices.
        """
        indices = [peer.idx for peer in self.config.peers]

        isolated_address = ipaddress.IPv4Address(self.config.isolated_address)
        isolated_network = ipaddress.IPv4Network(self.config.isolated_network)
        for host in isolated_network.hosts():
            if host == isolated_address:
                continue
            # IPv4/IPv6: picking the last byte, since we enforce a /24 network.
            idx = int(str(host).split('.')[3])
            if idx not in indices:
                return idx
        raise RuntimeError('unable to find a free index')

    def deploy_config(self):
        """
        Refresh the live config and reload the service.
        """
        wg_conf = Path(WG_ETC_DIR) / f'{self.config.isolated_interface}.conf'
        size1, digest1 = get_size_and_digest(wg_conf)

        lines = []
        lines.append('[Interface]')
        lines.append(f'Address = {self.config.isolated_address}/{WgManager.PREFIXLEN}')
        lines.append(f'ListenPort = {self.config.port}')
        lines.append(f'PrivateKey = {self.config.private_key}')

        for peer in self.config.peers:
            lines.append('')
            lines.append('[Peer]')
            lines.append(f'PublicKey = {peer.public_key}')
            # IPv4/IPv6: /32
            lines.append(f'AllowedIPs = {peer.get_ipv4_address(self.config.isolated_network)}/32')
            lines.append(f'PersistentKeepAlive = {DEFAULT_WG_PERSISTENT_KEEP_ALIVE}')

        # Atomic write:
        with wg_conf.with_suffix('.new') as new_wg_conf:
            new_wg_conf.touch(0o600)
            new_wg_conf.write_text(''.join([line + '\n' for line in lines]))
            new_wg_conf.rename(wg_conf)

        # Enable/restart unit if something changed:
        size2, digest2 = get_size_and_digest(wg_conf)
        if size1 != size2 or digest1 != digest2:
            self.set_service_state(self.config.isolated_interface, enable=True)

    def get_peer_config(self, idx: int):
        """
        Build the config file for the specified peer.
        """
        # Make sure the peer exists:
        peer = None
        for config_peer in self.config.peers:
            if config_peer.idx == idx:
                peer = config_peer
        if peer is None:
            raise RuntimeError(f'no peer with index={idx}')

        # We cannot build a config file if we don't have the private key for
        # that peer!
        if peer.private_key == '':
            raise RuntimeError(f'no private key available for index={idx}')

        lines = []
        lines.append('[Interface]')
        # IPv4/IPv6:
        lines.append(f'Address = {peer.get_ipv4_address(self.config.isolated_network)}'
                     f'/{WgManager.PREFIXLEN}')
        lines.append(f'PrivateKey = {peer.private_key}')
        # We want to see and manage DNS queries:
        lines.append(f'DNS = {self.config.isolated_address}')
        lines.append('')

        lines.append('[Peer]')
        lines.append(f'EndPoint = {self.config.public_external_address}:{self.config.port}')
        lines.append(f'PublicKey = {self.config.public_key}')
        # We want to route all traffic through the VPN:
        lines.append('AllowedIPs = 0.0.0.0/0')
        lines.append(f'PersistentKeepAlive = {DEFAULT_WG_PERSISTENT_KEEP_ALIVE}')

        return ''.join([line + '\n' for line in lines])


    def save_config(self, merge: bool = False):
        """
        Save our main configuration file.

        If refresh is set, and if a configuration file already exists, the
        current config is extended with the list of peers that's already around
        (making some noise about settings that changed) and with the key pair.

        Otherwise, make sure a key pair is generated, then save the current
        configuration.
        """
        old_interface = None

        config_path = Path(WG_VAR_DIR) / 'config.yaml'
        if config_path.exists() and merge:
            # We serialize via asdict() when saving the config file, so we need
            # to ** the dict we read back. The 'peers' attribute is a list of
            # dict/WgPeer, and that's managed via the __post_init__() method.
            old_config = WgConfig(**yaml.safe_load(config_path.read_text()))

            # Those are configurable via __init__() and might change over time:
            for attr in ['public_external_address', 'isolated_address', 'isolated_network',
                         'isolated_interface', 'port']:
                if getattr(self.config, attr) != getattr(old_config, attr):
                    logging.warning('%s attribute changed: %s → %s',
                                    attr,
                                    getattr(old_config, attr),
                                    getattr(self.config, attr))
                    # If the interface changed, we want to disable the old
                    # systemd unit:
                    if attr == 'interface':
                        old_interface = old_config.isolated_interface

            # Those need to be reloaded from the config file every time:
            self.config.private_key = old_config.private_key
            self.config.public_key = old_config.public_key
            self.config.peers = old_config.peers

        # Make sure we have a private/public key pair:
        if self.config.private_key == '' or self.config.public_key == '':
            self.config.private_key, self.config.public_key = self.generate_key_pair()

        # Atomic write:
        with config_path.with_suffix('.new') as new_config_path:
            new_config_path.touch(0o600)
            yaml.safe_dump(
                asdict(self.config),
                new_config_path.open('w'),
                sort_keys=False,
                default_flow_style=False,
                encoding="utf-8",
                allow_unicode=True,
            )
            new_config_path.rename(config_path)

        # Disable old unit if needed:
        if old_interface:
            self.set_service_state(old_interface, enable=False)

    def set_service_state(self, interface: str, enable: bool = True):
        """
        Enable/reload or disable the systemd unit as required.
        """
        unit = f'wg-quick@{interface}'
        if enable:
            # With enable|disable --now, both is-enabled and is-active should be
            # equivalent:
            if run(['systemctl', 'is-active', unit],
                   check=False, stdout=DEVNULL, stderr=DEVNULL).returncode != 0:
                logging.warning('enabling unit %s', unit)
                check_call(['systemctl', 'enable', '--now', unit])
            else:
                # Given wg-quick(8) and wg-quick@.service, using reload instead
                # of restart is probably sufficient, and a good idea (avoiding
                # disruption for active sessions):
                logging.warning('reloading unit %s', unit)
                check_call(['systemctl', 'reload', unit])
        else:
            logging.warning('disabling unit %s', unit)
            wg_conf = Path(WG_ETC_DIR) / f'{interface}.conf'
            wg_conf.unlink(missing_ok=True)
            check_call(['systemctl', 'disable', '--now', unit])

    def select_destination(self, idx: int, dest: Optional[Path], extension: str):
        """
        Build the filename to store the peer configuration.

        The generate_*() caller may pass dest=None and let us pick a name. In
        that case the comment is used if present, otherwise the default format
        string is used.

        In all cases, verify there's a peer matching the specified index.
        """
        # Let any exception bubble up (e.g. no such peer):
        peer = self.get(idx)

        # If the caller knows told us what to do, obey:
        if dest is not None:
            if isinstance(dest, str):
                return Path(dest)
            if isinstance(dest, Path):
                return dest
            raise ValueError('dest parameter is neither a str or a Path')

        # Otherwise use the comment, if available:
        if peer.comment != '':
            return Path(f'{peer.comment}.{extension}')

        # Final fallback:
        return Path(WgManager.PEER_CONFIG_FORMAT % {
            'idx': idx,
            'extension': extension,
        })

    @classmethod
    def validate_comment_format(cls, comment):
        """
        Initial implementation: any combinations (even empty) of letters,
        digits, dashes, underscores, and dots are OK.

        https://github.com/PiRogueToolSuite/pirogue-admin/issues/14

        """
        if comment == '':
            return True

        if re.match(r'^[0-9A-Za-z._-]*$', comment):
            return True

        return False
