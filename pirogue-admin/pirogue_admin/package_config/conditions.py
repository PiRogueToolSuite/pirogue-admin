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
from pirogue_admin.system_config import NetworkStack, detect_network_stacks


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
        # If the network stack is NM, the interface is fully configured through
        # it, so we must make sure hostapd is disabled:
        stacks = detect_network_stacks()
        if NetworkStack.NM in stacks:
            return False
        return True
    return False
