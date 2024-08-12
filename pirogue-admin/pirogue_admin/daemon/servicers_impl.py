import logging
import os
import platform
import random
import subprocess
import time
from pathlib import Path
from typing import List, Callable

import grpc
import yaml

from google.protobuf import empty_pb2
from google.protobuf.json_format import ParseDict, MessageToDict
from google.protobuf.wrappers_pb2 import StringValue

from pirogue_admin.cmd.cli import ADMIN_VAR_DIR
from pirogue_admin.system_config import OperatingMode, detect_external_ipv4_address
from pirogue_admin.system_config.wireguard import WgManager, WgPeer, WgConfig
from pirogue_admin_api import network_pb2, network_pb2_grpc
from pirogue_admin_api import system_pb2, system_pb2_grpc
from pirogue_admin_api import services_pb2, services_pb2_grpc
from pirogue_admin.package_config import ConfigurationContext, PackageConfigLoader
from pirogue_admin_api.system_pb2 import Configuration, ConfigurationTree, OperatingModeResponse
from pirogue_admin_api.network_pb2 import WifiConfiguration, VPNPeerList, VPNPeer
from pirogue_admin_api.services_pb2 import DashboardConfiguration, SuricataRulesSource, SuricataRulesSources

EMPTY = empty_pb2.Empty()

ADMIN_SELF_SIGNED_CERTIFICATE_PATH = '/var/lib/pirogue/admin/pirogue-external-exposure/fullchain.pem'


class SystemServicerImpl(system_pb2_grpc.SystemServicer):
    """
    Provides implementation for PiRogue admin System service.
    """
    def __init__(self, base_configuration_context: ConfigurationContext):
        self._base_configuration_context = base_configuration_context

    def register_to_server(self, server):
        system_pb2_grpc.add_SystemServicer_to_server(self, server)

    @property
    def _pcl(self) -> PackageConfigLoader:
        return PackageConfigLoader(self._base_configuration_context)

    def GetConfiguration(self, request, context):
        logging.debug('current_config:', self._pcl.current_config)
        current_config = self._pcl.current_config
        # Prevent native type into message
        sanitized_current_config = dict(map(lambda kv: (kv[0], str(kv[1])), current_config.items()))
        cfg = Configuration(variables=sanitized_current_config)
        return cfg

    # def ApplyConfiguration(self, request, context):
    #     configuration = MessageToDict(request)
    #     try:
    #         self._pcl.apply_configuration(configuration)
    #     except ValueError as err:
    #         context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
    #         context.set_details(str(err))
    #         raise err
    #     return EMPTY

    def GetConfigurationTree(self, request, context):
        whole_map = self._pcl.get_configuration_tree()

        ctree = ConfigurationTree()
        ParseDict(whole_map, ctree)

        return ctree

    def GetOperatingMode(self, request, context):
        op_answer = OperatingModeResponse()
        op_answer.mode = system_pb2.OPERATING_MODE_UNSPECIFIED

        if 'SYSTEM_OPERATING_MODE' in self._pcl.current_config:
            op = OperatingMode(self._pcl.current_config['SYSTEM_OPERATING_MODE'])
            if op == OperatingMode.AP:
                op_answer.mode = system_pb2.OPERATING_MODE_ACCESS_POINT
            elif op == OperatingMode.VPN:
                op_answer.mode = system_pb2.OPERATING_MODE_VPN
            elif op == OperatingMode.APPLIANCE:
                op_answer.mode = system_pb2.OPERATING_MODE_APPLIANCE

        return op_answer

    def GetHostname(self, request, context):
        result = subprocess.check_output(['hostname'])
        return StringValue(value=result.strip())

    # TODO: SetHostname

    def GetLocale(self, request, context):
        result = os.getenv('LANG')
        return StringValue(value=result)

    # TODO: SetLocale

    def GetTimezone(self, request, context):
        result = subprocess.check_output(['timedatectl', '-p', 'Timezone', '--value', 'show'])
        return StringValue(value=result.strip())

    # TODO: SetTimezone

    # TODO: ListConnectedDevices


class NetworkServicerImpl(network_pb2_grpc.NetworkServicer):
    def __init__(self,
                 base_configuration_context: ConfigurationContext,
                 get_port_func: Callable[[], str],
                 get_token_func: Callable[[], str],
                 reset_token_func: Callable[[], None]):
        self._base_configuration_context = base_configuration_context
        self._get_port_func = get_port_func
        self._get_token_func = get_token_func
        self._reset_token_func = reset_token_func

    def register_to_server(self, server):
        network_pb2_grpc.add_NetworkServicer_to_server(self, server)

    @property
    def _pcl(self) -> PackageConfigLoader:
        return PackageConfigLoader(self._base_configuration_context)

    @property
    def _wgm(self) -> WgManager:
        public_external_address = None
        isolated_address = None
        isolated_network = None
        config_path = Path(ADMIN_VAR_DIR) / 'config.yaml'
        if config_path.exists():
            config = yaml.safe_load(config_path.read_text())
            if 'PUBLIC_EXTERNAL_ADDRESS' in config:
                public_external_address = config['PUBLIC_EXTERNAL_ADDRESS']
            else:
                raise RuntimeError('invalid wireguard VPN configuration: missing PUBLIC_EXTERNAL_ADDRESS')
            if 'ISOLATED_ADDRESS' in config:
                isolated_address = config['ISOLATED_ADDRESS']
            else:
                raise RuntimeError('invalid wireguard VPN configuration: missing ISOLATED_ADDRESS')
            if 'ISOLATED_NETWORK' in config:
                isolated_network = config['ISOLATED_NETWORK']
            else:
                raise RuntimeError('invalid wireguard VPN configuration: missing ISOLATED_NETWORK')
        else:
            raise RuntimeError('wireguard VPN is not configured')

        # Use strings all the time, making things easier with serialization to and
        # deserialization from the yaml config file used by the WireGuard manager:
        manager = WgManager(
            public_external_address,
            isolated_address,
            isolated_network,
        )
        return manager

    def GetWifiConfiguration(self, request, context):
        current_config = self._pcl.current_config
        response = WifiConfiguration()
        if 'WIFI_SSID' in current_config:
            response.ssid = current_config['WIFI_SSID']
        if 'WIFI_PASSPHRASE' in current_config:
            response.passphrase = current_config['WIFI_PASSPHRASE']
        if 'WIFI_COUNTRY_CODE' in current_config:
            response.country_code = current_config['WIFI_COUNTRY_CODE']
        return response

    def SetWifiConfiguration(self, request, context):
        logging.debug(f'SetWifiConfiguration: {request}')
        configuration = MessageToDict(request, preserving_proto_field_name=True)
        logging.debug(f'configuration: {configuration}')
        config_to_apply = {}
        if 'ssid' in configuration:
            config_to_apply['WIFI_SSID'] = configuration['ssid']
        if 'passphrase' in configuration:
            config_to_apply['WIFI_PASSPHRASE'] = configuration['passphrase']
        if 'country_code' in configuration:
            config_to_apply['WIFI_COUNTRY_CODE'] = configuration['country_code']
        if len(config_to_apply) > 0:
            self._pcl.apply_configuration(config_to_apply)
        return EMPTY

    def ListVPNPeers(self, request, context):
        # mock:
        # peers = []
        # for idx in range(1,10):
        #     peers.append(WgPeer(idx=idx, comment=f'comment {idx}', public_key=f'pubk {idx}', private_key=f'pubk {idx}'))
        peers = self._wgm.list()
        response = VPNPeerList()
        for peer in peers:
            response.peers.append(VPNPeer(idx=peer.idx, comment=peer.comment, public_key=peer.public_key, private_key=peer.private_key))
        return response

    def GetVPNPeer(self, request, context):
        idx = request.value
        # mock:
        # peer = WgPeer(idx=idx, comment=f'comment {idx}', public_key=f'pubk {idx}', private_key=f'pubk {idx}')
        peer = self._wgm.get(idx)
        response = VPNPeer(idx=peer.idx, comment=peer.comment, public_key=peer.public_key, private_key=peer.private_key)
        return response

    def AddVPNPeer(self, request, context):
        add_request = MessageToDict(request, preserving_proto_field_name=True)
        print('add_request:', add_request)
        add_comment = ''
        add_public_key = ''
        if 'comment' in add_request:
            add_comment = add_request['comment']
        if 'public_key' in add_request:
            add_public_key = add_request['public_key']
        # mock:
        # idx = random.randint(1000, 9999)
        # peer = WgPeer(idx=idx, comment=f'comment {idx}', public_key=f'pubk {idx}', private_key=f'pubk {idx}')
        peer = self._wgm.add(comment=add_comment, public_key=add_public_key)
        response = VPNPeer(idx=peer.idx, comment=peer.comment, public_key=peer.public_key, private_key=peer.private_key)
        return response

    def DeleteVPNPeer(self, request, context):
        idx = request.value
        # mock:
        # peer = WgPeer(idx=idx, comment=f'comment {idx}', public_key=f'pubk {idx}', private_key=f'pubk {idx}')
        peer = self._wgm.delete(idx)
        response = VPNPeer(idx=peer.idx, comment=peer.comment, public_key=peer.public_key, private_key=peer.private_key)
        return response

    def GetVPNPeerConfig(self, request, context):
        idx = request.value
        # mock:
        # config = (f''
        #           f'[Interface]\n'
        #           f'Address = 1.2.3.{idx}\n'
        #           f'PrivateKey = prvk{idx}\n'
        #           f'DNS = 9.8.7.6\n'
        #           f'\n'
        #           f'[Peer]\n'
        #           f'EndPoint = 9.8.7.7:56000\n'
        #           f'PublicKey = pubk{idx}\n'
        #           f'AllowedIPs = 0.0.0.0/0\n'
        #           f'PersistentKeepAlive = True')
        config = self._wgm.get_peer_config(idx)
        return StringValue(value=config)

    def ResetAdministrationToken(self, request, context):
        self._reset_token_func()
        return StringValue(value=self._get_token_func())

    def GetAdministrationToken(self, request, context):
        return StringValue(value=self._get_token_func())

    def GetAdministrationCertificate(self, request, context):
        certificate = Path(ADMIN_SELF_SIGNED_CERTIFICATE_PATH).read_text()
        return StringValue(value=certificate)

    def GetAdministrationCLIs(self, request, context):
        current_config = self._pcl.current_config
        port = self._get_port_func()
        token = self._get_token_func()
        external_address = current_config['EXTERNAL_ADDRESS']

        clis = list()
        clis.append(f"# One time client configuration")
        clis.append(f"pirogue-admin-client"
                    f" --save"
                    f" --host '{external_address}'"
                    f" --port {port}"
                    f" --token {token}")
        clis.append(f"# Then, use directly")
        clis.append(f"pirogue-admin-client system get-configuration")
        return StringValue(value='\n'.join(clis))

    def EnableExternalPublicAccess(self, request, context):
        enable_request = MessageToDict(request, preserving_proto_field_name=True)
        new_conf_to_apply = {
            'PUBLIC_DOMAIN_NAME': enable_request['domain'],
            'PUBLIC_CONTACT_EMAIL': enable_request['email'],
            'ENABLE_PUBLIC_ACCESS': True,
        }
        current_config = self._pcl.apply_configuration(new_conf_to_apply)
        return EMPTY

    def DisableExternalPublicAccess(self, request, context):
        new_conf_to_apply = {
            'ENABLE_PUBLIC_ACCESS': False,
        }
        current_config = self._pcl.apply_configuration(new_conf_to_apply)
        return EMPTY


class ServicesServicerImpl(services_pb2_grpc.ServicesServicer):

    def __init__(self, base_configuration_context: ConfigurationContext):
        self._base_configuration_context = base_configuration_context

    def register_to_server(self, server):
        services_pb2_grpc.add_ServicesServicer_to_server(self, server)

    @property
    def _pcl(self) -> PackageConfigLoader:
        return PackageConfigLoader(self._base_configuration_context)

    def GetDashboardConfiguration(self, request, context):
        current_config = self._pcl.current_config
        response = DashboardConfiguration()
        if 'DASHBOARD_PASSWORD' in current_config:
            response.password = current_config['DASHBOARD_PASSWORD']
        return response

    def SetDashboardConfiguration(self, request, context):
        configuration = MessageToDict(request, preserving_proto_field_name=True)
        config_to_apply = {}
        if 'password' in configuration:
            config_to_apply['DASHBOARD_PASSWORD'] = configuration['password']
        if len(config_to_apply) > 0:
            self._pcl.apply_configuration(config_to_apply)
        return EMPTY

    def ListSuricataRulesSources(self, request, context):
        response = SuricataRulesSources()
        for source_path in Path('/var/lib/suricata/update/sources').glob('*.yaml'):
            if source_path.is_dir():
                continue
            if source_path.is_symlink():
                continue
            source_config = yaml.safe_load(source_path.read_text())
            if 'url' not in source_config:
                continue
            response.sources.append(SuricataRulesSource(
                name=source_config['source'],
                url=source_config['url'],
            ))
        return response
