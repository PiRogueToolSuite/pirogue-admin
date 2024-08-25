"""
This module defines a mapping between types and formatters, so that variables
can be used to generate text to be substituted in configuration files.

Initially, only one value was passed to each formatter (the value of the
variable to format), to be turned into the desired representation. Now we're
also passing the dict with all variables, as at least the dhcp_range_network
type requires two variables (see its docstring).

For the time being, that dict is unused in all other functions.
"""

import ipaddress
import re
from functools import wraps


# This dict is automatically filled thanks to the decorator used for the
# following functions:
SUPPORTED_FORMATTERS = {}


def formatter(func):
    """
    Map format_<type> function to each <type>.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    SUPPORTED_FORMATTERS[re.sub(r'^format_', '', func.__name__)] = func
    return wrapper


@formatter
def format_string(value: str,
                  _variables: dict[str, str]):
    """
    Strings are copied/pasted (the vast majority of cases).
    """
    return value


@formatter
def format_bool(value: bool,
                _variables: dict[str, str]):
    """
    For the time being we only have a single bool, and all we need is to make
    sure it gets turned into a string so that the generic template replacement
    doesn't bail out.

    Let's go for an explicit conversion via str(), but we could use anything,
    like a JSON-like representation.
    """
    return str(value)


@formatter
def format_cidr_network(value: str,
                        _variables: dict[str, str]):
    """
    For now, it's likely we'll store the network as a string, using the
    a.b.c.d/n notation, so we could use format_string() as well, but maybe we'll
    store that differently (e.g. as an IPv4Network directly) so let's be
    explicit about what we want to output.
    """
    network = ipaddress.IPv4Network(value)
    return network.with_prefixlen


@formatter
def format_dhcp_range_line(value: str,
                           variables: dict[str, str]):
    """
    This one is tricky, as it actually requires multiple values: the network
    itself, the PiRogue's own IP address (the computed range cannot contain it),
    and whether to enable the DHCP feature in the first place.

    This is why in addition to the usual first argument (value = the network we
    want to build a DHCP range for), we look into the second argument (a dict
    with all variable names/values) to get the PiRogue IP's own IP address,
    and whether to enable DHCP.

    Hardcoding this is a bit nasty, keeps processing index.yaml files (see
    PackageConfig class) manageable.
    """

    if not variables['ENABLE_DHCP']:
        return '# dhcp-range is disabled'

    # Those really should be set/validated by pirogue-admin already, so
    # shouldn't raise any exceptions:
    network = ipaddress.IPv4Network(value)
    address = ipaddress.IPv4Address(variables['ISOLATED_ADDRESS'])

    # Let's make sure both are consistent:
    hosts = list(network.hosts())
    if address not in hosts:
        raise ValueError(f'network {value} does not contain address {address}')

    # Take the bigger range:
    index = hosts.index(address)
    if index >= len(hosts)/2:
        hosts = hosts[0:index]
    else:
        hosts = hosts[index+1:]

    # Final sanity check:
    if not hosts:
        raise ValueError(f'network {value} is too small to get a DHCP range!')

    # str(), .compressed, and .exploded are the same for IPv4. Let's go for an
    # explicit str():
    return f'dhcp-range={str(hosts[0])},{str(hosts[-1])},24h'


@formatter
def format_grafana_re_positive_match_network(value: str,
                                             _variables: dict[str, str]):
    """
    Grafana's regex support is full of surprises (take 1).

    Let's go for simple things first, supporting full-byte prefixes.

    FIXME: a.b.c.* works for /24 but:
     - Should that be a.b.*.* or a.b.* for /16?
     - Should that be a.*.*.* or a.*   for /8?

    The code below implements the latter.

    FIXME: See how to deal with e.g. a /28 or a /20. For small ranges, listing
    individual address might work. For bigger ranges, listing individual subnets
    might work.
    """
    network = ipaddress.IPv4Network(value)
    if network.prefixlen in [8, 16, 24]:
        prefix_bytes = str(network.network_address).split('.')[0:int(network.prefixlen/8)]
        return f'=~ /{".".join(prefix_bytes)}.*/'
    raise ValueError(f'unsupported prefix len {network.prefixlen}, must be multiple of 8')


@formatter
def format_grafana_re_negative_match_address(value: str,
                                             _variables: dict[str, str]):
    """
    Grafana's regex support is full of surprises (take 2).

    FIXME: Check we really need to anchor the regex on the right, which we don't
    do on the left, either here or in format_grafana_re_positive_match_network().
    """
    return f'!~ /{value}$/'
