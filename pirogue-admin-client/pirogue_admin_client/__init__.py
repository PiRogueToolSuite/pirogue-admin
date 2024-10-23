from cryptography import x509
from enum import Enum
from pathlib import Path

import grpc
import yaml
from cryptography.x509.oid import NameOID

from pirogue_admin_api import PIROGUE_ADMIN_TCP_PORT
from pirogue_admin_client.adapters import SystemAdapter, NetworkAdapter, ServicesAdapter, access_token_call_credentials

ADMIN_VAR_DIR = '/var/lib/pirogue/admin'
USERLAND_CLIENT_CONFIG_FILENAME = '.pirogue-admin-client.conf'


class PirogueAdminClientAdapter(SystemAdapter, NetworkAdapter, ServicesAdapter):
    _host: str
    _port: int
    _token: str
    _certificate: str

    def __init__(self, host: str = None, port: int = None,
                 token: str = None, certificate: str = None):
        self._host = host
        self._port = port
        self._token = token
        self._certificate = certificate

        self._local_pirogue_client_config_path = Path(ADMIN_VAR_DIR, 'client.yaml')
        self._userland_client_config_path = Path(Path.home(), USERLAND_CLIENT_CONFIG_FILENAME)

        # _use_tls will be updated by _load_configuration
        self._use_tls = False
        self._load_configuration()

        chan_str = f'{self._host}:{self._port}'
        token_call_injector = access_token_call_credentials(self._token)

        secure_channel = grpc.ssl_channel_credentials(
            str.encode(self._certificate) if (self._certificate is not None and
                                              self._certificate != 'public') else None)
        local_channel = grpc.local_channel_credentials(grpc.LocalConnectionType.LOCAL_TCP)

        composite_credentials = grpc.composite_channel_credentials(
            secure_channel if self._use_tls else local_channel,
            token_call_injector,
        )

        options = ()
        if self._certificate is not None and self._certificate != 'public':
            cert_decoded = x509.load_pem_x509_certificate(str.encode(self._certificate))
            (common_name,) = cert_decoded.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn_target = common_name.value
            options = (('grpc.ssl_target_name_override', f'{cn_target}',),)

        channel = grpc.secure_channel(chan_str, composite_credentials, options)

        super(PirogueAdminClientAdapter, self).__init__(channel)

    def _load_configuration(self):
        loaded_config = None

        if self._local_pirogue_client_config_path.exists():
            loaded_config = yaml.safe_load(self._local_pirogue_client_config_path.read_text())
        elif self._userland_client_config_path.exists():
            loaded_config = yaml.safe_load(self._userland_client_config_path.read_text())

        if isinstance(loaded_config, dict):  # Prevents existing but empty file
            self._host = loaded_config['host'] if self._host is None else self._host
            self._port = loaded_config['port'] if self._port is None else self._port
            self._token = loaded_config['token'] if self._token is None else self._token
            # Support previous existing version
            # where 'certificate' key could not be present
            if 'certificate' in loaded_config:
                if self._certificate is None:
                    self._certificate = loaded_config['certificate']

        self._host = 'localhost' if self._host is None else self._host
        self._port = PIROGUE_ADMIN_TCP_PORT if self._port is None else self._port

        self._use_tls = self._host not in ['localhost', '127.0.0.1', 'ip6-localhost']

        if self._host in (None, ''):
            raise RuntimeError("Can't connect without host parameter")
        if self._port in (None, '', 0):
            raise RuntimeError("Can't connect without port parameter")
        if self._token in (None, ''):
            raise RuntimeError("Can't connect without token parameter")

    def save_configuration(self):
        if self._local_pirogue_client_config_path.exists():
            raise RuntimeError('Cannot save configuration on PiRogue, this may interfere with daemon configuration')
        else:
            with open(self._userland_client_config_path, 'w') as out_fs:
                yaml.safe_dump({
                        'host': self._host,
                        'port': self._port,
                        'token': self._token,
                        'certificate': 'public' if self._certificate is None else self._certificate,
                    }, out_fs)

