"""
This module defines a mapping between conditions and their implementations.

Each condition implementation might look at the running system (loaded kernel
modules, available interfaces, filesystem contents) and/or at the variables.
Those are expected to be passed to each function, even if they're not useful.
"""

import re
import subprocess
from functools import wraps

from pirogue_admin.system_config import OperatingMode, SystemConfig


def get_iptables_alternatives_value():
    """
    DRY for the iptables/nftables functions.
    """
    output = subprocess.check_output(['update-alternatives', '--query', 'iptables'])
    for line in output.decode().splitlines():
        if line.startswith('Value: '):
            return line[len('Value: '):]
    raise ValueError('could not determine the current value of the iptables alternatives')


# This dict is automatically filled thanks to the decorator (factory) used for
# the following methods, each condition points to a function and to a list of
# variables that are required for proper operation.
SUPPORTED_CONDITIONS = {}


def conditioner(variables: list):
    """
    Augment (inner) conditioner decorator with a list of variables.
    """
    def conditioner_inner(func):
        """
        Map condition_<name> implementation to each condition <NAME>.

        Note that contrary to formatters, conditions are written in uppercase in the
        index.yaml files (mainly for visibility). We store two things for those: a
        function to call, and the required variables.
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        SUPPORTED_CONDITIONS[re.sub(r'^condition_', '', func.__name__).upper()] = {
            'function': func,
            'variables': variables,
        }
        return wrapper
    return conditioner_inner


@conditioner([
    f'{SystemConfig.PREFIX}OPERATING_MODE',
])
def condition_hostapd_needed(variables: dict[str, str]):
    """
    This one depends on the selected mode of operation, which doesn't appear
    anywhere in the variables that have been accumulated from the various
    index.yaml files.

    Basically: only if the “access point” mode is selected.
    """
    mode = OperatingMode(variables[f'{SystemConfig.PREFIX}OPERATING_MODE'])
    if mode == OperatingMode.AP:
        return True
    return False


@conditioner([])
def condition_iptables_mode(_variables: dict[str, str]):
    """
    Ask the alternatives system about the iptables/nftables situation.

    FIXME: Is that actually reliable?
    """
    return get_iptables_alternatives_value().endswith('-legacy')


@conditioner([])
def condition_nftables_mode(_variables: dict[str, str]):
    """
    Ask the alternatives system about the iptables/nftables situation.

    FIXME: Is that actually reliable?
    """
    return get_iptables_alternatives_value().endswith('-nft')
