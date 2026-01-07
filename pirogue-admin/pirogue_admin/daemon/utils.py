import logging
import psutil
import shutil
import subprocess

from functools import reduce
from pystemd.systemd1 import Unit


def json_chain(json_obj, keys):
    """
    Traverse json_obj with keys dotted chain expression if exists.
    Returns None otherwise.
    Assuming json_obj is {a: {b: {c: bar}}
    with keys: 'a.b.c' returns bar
    with keys: 'a.foo.c' return None
    """
    try:
        return reduce(
            lambda x, y: x[int(y)] if y.isdigit() else x.get(y, None),
            keys.split('.'), json_obj)
    except AttributeError:
        return None
    except KeyError:
        return None
    except IndexError:
        return None


def get_install_packages(pattern: str) -> list[dict]:
    if shutil.which('dpkg-query') is None:
        # Not running on Raspbian/Ubuntu/Debian
        return []

    cmd = [
        'dpkg-query',
        '--showformat',
        '${db:Status-Want}\t'
        '${db:Status-Status}\t'
        '${db:Status-Eflag}\t'
        '${Package}\t'
        '${Version}\n',
        '-W',
        f'{pattern}'
    ]

    packages = []
    try:
        output = subprocess.check_output(cmd)
        for line_bytes in output.splitlines():
            line = line_bytes.decode('utf-8')
            want, status, error, package, version = line.split('\t')
            if want != 'install':
                continue
            packages.append({
                'package': package,
                'version': version,
                'state': status,
                'status': error,
            })
        return packages
    except Exception as e:
        logging.error(e)
        return []


def get_system_usage_percent() -> dict:
    ram_usage = psutil.virtual_memory()
    disk_usage = psutil.disk_usage('/')
    return {
        'ram_percent': ram_usage.percent,
        'disk_percent': disk_usage.percent,
    }


def get_service_status(service_name: str) -> str:
    unit = Unit(f'{service_name}')
    unit.load()
    load_state = unit.Unit.LoadState.decode('utf-8')
    if load_state != 'loaded':
        return load_state
    return unit.Unit.ActiveState.decode('utf-8')
