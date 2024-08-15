"""
This module defines a mapping between conditions and their implementations.

Each condition implementation might look at the running system (loaded kernel
modules, available interfaces, filesystem contents) and/or at the variables.
Those are expected to be passed to each function, even if they're not useful.
"""

import re
import subprocess
from functools import wraps


def get_iptables_alternatives_value():
    """
    DRY for the iptables/nftables functions.
    """
    output = subprocess.check_output(['update-alternatives', '--query', 'iptables'])
    for line in output.decode().splitlines():
        if line.startswith('Value: '):
            return line[len('Value: '):]
    raise ValueError('could not determine the current value of the iptables alternatives')


# This dict is automatically filled thanks to the decorator used for the
# following methods:
SUPPORTED_CONDITIONS = {}


def conditioner(func):
    """
    Map condition_<name> implementation to each condition <NAME>.

    Note that contrary to formatters, conditions are written in uppercase in the
    index.yaml files (mainly for visibility).
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    SUPPORTED_CONDITIONS[re.sub(r'^condition_', '', func.__name__).upper()] = func
    return wrapper


@conditioner
def condition_dnsmasq_needed(variables: dict[str, str]):
    """
    This one depends on the selected mode of operation, which doesn't appear
    anywhere in the variables that have been accumulated from the various
    index.yaml files.

    Basically: definitely if we're in “access point” mode; but only optionally
    if we're in “appliance” mode, if admins told us to manage DHCP/DNS on the
    isolated network. This could be managed by a different equipment, e.g.
    a physical access point deals with those topics, and we only collect get the
    traffic routed through us.

    """
    # FIXME (again): let's pretend pirogue-admin supports internal variables,
    # whose names are prefixed with an underscore. _MODE is an absolute must,
    # while _DNSMASQ might only stay optional (let's go for a safe default
    # value):
    if variables['_MODE'] == 'access-point':
        return True
    if variables['_MODE'] == 'appliance':
        if variables.get('_DNSMASQ', False):
            return True
    # FIXME: Adjust once we know more about the inner workings of wireguard.
    return False


@conditioner
def condition_hostapd_needed(variables: dict[str, str]):
    """
    This one depends on the selected mode of operation, which doesn't appear
    anywhere in the variables that have been accumulated from the various
    index.yaml files.

    Basically: only if the “access point” mode is selected.
    """
    # FIXME (again): let's pretend pirogue-admin supports internal variables,
    # whose names are prefixed with an underscore.
    if variables['_MODE'] == 'access-point':
        return True
    return False


@conditioner
def condition_iptables_mode(_variables: dict[str, str]):
    """
    Ask the alternatives system about the iptables/nftables situation.

    FIXME: Is that actually reliable?
    """
    return get_iptables_alternatives_value().endswith('-legacy')


@conditioner
def condition_nftables_mode(_variables: dict[str, str]):
    """
    Ask the alternatives system about the iptables/nftables situation.

    FIXME: Is that actually reliable?
    """
    return get_iptables_alternatives_value().endswith('-nft')
