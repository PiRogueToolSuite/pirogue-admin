import grpc
import json
import logging
import os
import subprocess

from pathlib import Path
from typing import Callable, Dict

import yaml

from google.protobuf import empty_pb2
from google.protobuf.json_format import ParseDict, MessageToDict
from google.protobuf.wrappers_pb2 import StringValue

from .utils import (
    json_chain,
    get_install_packages,
    get_service_status,
    get_system_usage_percent,
)
from pirogue_admin.daemon.user_access import (
    IllegalPermissionError,
    UserAccess as UserAccess_Internal,
    UserAccessRegistry,
)
from pirogue_admin.system_config import OperatingMode
from pirogue_admin.system_config.wireguard import WgManager
from pirogue_admin_api import network_pb2, network_pb2_grpc
from pirogue_admin_api import system_pb2, system_pb2_grpc
from pirogue_admin_api import services_pb2, services_pb2_grpc
from pirogue_admin_api import access_pb2, access_pb2_grpc
from pirogue_admin.package_config import ConfigurationContext, PackageConfigLoader
from pirogue_admin_api.system_pb2 import (
    Configuration,
    ConfigurationTree,
    OperatingModeResponse,
    PackagesInfo,
    PackageInfo,
    Status,
    SectionStatus,
    ItemInfo,
)
from pirogue_admin_api.network_pb2 import (
    IsolatedPort,
    IsolatedPortList,
    WifiConfiguration,
    VPNPeerList,
    VPNPeer,
)
from pirogue_admin_api.services_pb2 import (
    DashboardConfiguration,
    SuricataRulesSource,
    SuricataRulesSources,
)
from pirogue_admin_api.access_pb2 import (
    MethodAccess,
    ServiceAccess,
    UserAccess,
    UserAccessList,
    PermissionChanges,
)

EMPTY = empty_pb2.Empty()

ADMIN_SELF_SIGNED_CERTIFICATE_PATH = 'pirogue-external-exposure/fullchain.pem'

logger = logging.getLogger(__name__)

def _cross_servicer_wireguard_manager(ctx: ConfigurationContext) -> WgManager:
    """
    Provides WgManager instance across servicer.
    Does not depend on servicer internal states.
    """
    public_external_address = None
    isolated_address = None
    isolated_network = None
    config_path = Path(ctx.var_dir, 'config.yaml')
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
        logger.debug('current_config:', self._pcl.current_config)
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

    def GetStatus(self, request, context):
        current_config = self._pcl.current_config

        isolated_interface = current_config['ISOLATED_INTERFACE']

        # System status
        system_usage_percents = get_system_usage_percent()
        system_status = SectionStatus(name='system', description='System status')
        system_status.items.append(ItemInfo(
            name='ram-percent', description='RAM usage percentage',
            state=str(system_usage_percents['ram_percent'])
        ))
        system_status.items.append(ItemInfo(
            name='disk-percent', description='DISK usage percentage',
            state=str(system_usage_percents['disk_percent'])
        ))
        system_status.items.append(ItemInfo(
            name='operating-mode', description='Current operating mode',
            state=current_config['SYSTEM_OPERATING_MODE']
        ))
        system_status.items.append(ItemInfo(
            name='admin-daemon', description='Administration daemon',
            state=get_service_status('pirogue-admin.service')
        ))
        system_status.items.append(ItemInfo(
            name='isolated-interface', description='Isolated interface',
            state=current_config['ISOLATED_INTERFACE']
        ))
        system_status.items.append(ItemInfo(
            name='external-interface', description='External interface',
            state=current_config['EXTERNAL_INTERFACE']
        ))

        # Dashboard status
        dashboard_status = SectionStatus(name='dashboard', description='Dashboard status')
        dashboard_status.items.append(ItemInfo(
            name='grafana', description='Grafana server service',
            state=get_service_status('grafana-server.service')
        ))

        dashboard_status.items.append(ItemInfo(
            name='influxdb', description='InfluxDB server service',
            state=get_service_status('influxdb.service')
        ))

        # Maintenance status
        maintenance_status = SectionStatus(name='maintenance', description='Maintenance status')
        maintenance_status.items.append(ItemInfo(
            name='pirogue', description='Daily pirogue maintenance',
            state=get_service_status('pirogue-maintenance.timer')
        ))
        maintenance_status.items.append(ItemInfo(
            name='certificates', description='Weekly certificate maintenance',
            state=get_service_status('pirogue-external-exposure.timer')
        ))

        # Networking status
        networking_status = SectionStatus(name='networking', description='Networking status')
        networking_status.items.append(ItemInfo(
            name='vpn', description='VPN service',
            state=get_service_status(f'wg-quick@{isolated_interface}.service')
        ))
        networking_status.items.append(ItemInfo(
            name='nftables', description='Firewall nftables service',
            state=get_service_status('nftables.service')
        ))
        networking_status.items.append(ItemInfo(
            name='suricata', description='Suricata rules service',
            state=get_service_status('suricata.service')
        ))
        networking_status.items.append(ItemInfo(
            name='evidence-collector', description='Evidence collector service',
            state=get_service_status('pirogue-eve-collector.service')
        ))
        networking_status.items.append(ItemInfo(
            name='flow-inspector', description='Flow inspector service',
            state=get_service_status(f'pirogue-flow-inspector@{isolated_interface}.service')
        ))
        networking_status.items.append(ItemInfo(
            name='dhcp-client', description='DHCP client service',
            state=get_service_status('dhcpcd.service')
        ))
        networking_status.items.append(ItemInfo(
            name='dns', description='DNS masquerade service',
            state=get_service_status('dnsmasq.service')
        ))
        networking_status.items.append(ItemInfo(
            name='access-point', description='Access point service',
            state=get_service_status('hostapd.service')
        ))
        networking_status.items.append(ItemInfo(
            name='external-exposure', description='External exposure to internet',
            state='accessible' if current_config['ENABLE_PUBLIC_ACCESS'] else 'closed'
        ))
        networking_status.items.append(ItemInfo(
            name='external-domain-name', description='External domain name',
            state=current_config['PUBLIC_DOMAIN_NAME']
        ))

        #_cross_servicer_wireguard_manager()

        answer = Status()
        answer.sections.append(system_status)
        answer.sections.append(dashboard_status)
        answer.sections.append(maintenance_status)
        answer.sections.append(networking_status)

        return answer

    def GetPackagesInfo(self, request, context):
        package_states = get_install_packages("*pirogue*")

        answer = PackagesInfo()

        for package_state in package_states:
            pi = PackageInfo(**package_state)
            answer.packages.append(pi)

        return answer

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
                 get_port_func: Callable[[], int],
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
        return _cross_servicer_wireguard_manager(self._base_configuration_context)

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
        logger.debug(f'SetWifiConfiguration: {request}')
        configuration = MessageToDict(request, preserving_proto_field_name=True)
        logger.debug(f'configuration: {configuration}')
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

    def EnableExternalPublicAccess(self, request, context):
        enable_request = MessageToDict(request, preserving_proto_field_name=True)
        new_conf_to_apply = {
            'PUBLIC_DOMAIN_NAME': enable_request['domain'],
            'PUBLIC_CONTACT_EMAIL': enable_request['email'],
            'ENABLE_PUBLIC_ACCESS': True,
        }

        logger.info('enabling external public access')

        current_config = self._pcl.apply_configuration(new_conf_to_apply)
        return EMPTY

    def DisableExternalPublicAccess(self, request, context):
        current_config = self._pcl.current_config

        # Restores a default FQDN before
        # returning back to self-signed cert
        new_conf_to_apply = {
            'ENABLE_PUBLIC_ACCESS': False,
            'PUBLIC_DOMAIN_NAME': f"{current_config['SYSTEM_HOSTNAME']}.local",
        }

        logger.info('disabling external public access')

        current_config = self._pcl.apply_configuration(new_conf_to_apply)
        return EMPTY

    def _list_opened_ports(self):
        json_result = subprocess.check_output(['nft', '-j', 'list', 'chain', 'inet', 'filter', 'pirogue_admin_chain'])
        result = json.loads(json_result)
        ports = {}
        if 'nftables' in result:
            for section in result['nftables']:
                if 'rule' not in section:
                    continue
                rule_section = section['rule']

                if json_chain(rule_section, 'expr.0.match.left.meta.key') == 'iifname':
                    if json_chain(rule_section, 'expr.1.match.left.payload.field') != 'dport':
                        continue
                    dport = json_chain(rule_section, 'expr.1.match.right')
                    if dport is None:
                        continue
                    handle = rule_section['handle']

                    if str(dport) not in ports:
                        ports[str(dport)] = {}
                    ports[str(dport)]['handle_iif'] = str(handle)

                if json_chain(rule_section, 'expr.0.match.left.meta.key') == 'oifname':
                    if json_chain(rule_section, 'expr.1.match.left.payload.field') != 'sport':
                        continue
                    sport = json_chain(rule_section, 'expr.1.match.right')
                    if sport is None:
                        continue

                    handle = rule_section['handle']

                    if str(sport) not in ports:
                        ports[str(sport)] = {}

                    ports[str(sport)]['handle_oif'] = str(handle)

        return ports

    def ListIsolatedOpenPorts(self, request, context):
        """
        nft -j list chain inet filter pirogue_admin_chain
        """

        response = IsolatedPortList()

        _ports = self._list_opened_ports()

        for port_key in _ports:
            response.ports.append(IsolatedPort(port=int(port_key)))

        return response

    def OpenIsolatedPort(self, request, context):
        """
        Add nf-table rule to accept and forward tcp trafic on the given port
        to localhost.
        Equivalent to the following command lines:
        nft add rule inet filter pirogue_admin_chain iifname wg0 tcp dport 8080 accept
        nft add rule inet filter pirogue_admin_chain oifname wg0 tcp sport 8080 tcp dport 8080
        """

        current_config = self._pcl.current_config

        _ports = self._list_opened_ports()

        requested_port = str(request.port)

        if requested_port in _ports:
            raise ValueError(f"port {requested_port} already opened")

        logger.info(f'opening isolated port: {requested_port}')

        open_step_1_result = subprocess.check_output([
            'nft', 'add', 'rule', 'inet', 'filter', 'pirogue_admin_chain',
            'iifname', current_config['ISOLATED_INTERFACE'],
            'tcp', 'dport', requested_port,
            'accept'])

        open_step_2_result = subprocess.check_output([
            'nft', 'add', 'rule', 'inet', 'filter', 'pirogue_admin_chain',
            'oifname', current_config['ISOLATED_INTERFACE'],
            'tcp', 'sport', requested_port,
            'tcp', 'dport', requested_port])

        return EMPTY

    def CloseIsolatedPort(self, request, context):
        """
        Stop accepting connections on the given port (if specified),
        Flush all rules otherwise.
        Equivalent to the following command line:
        nft flush chain inet filter pirogue_admin_chain
        """

        if request.port:
            _ports = self._list_opened_ports()

            requested_port = str(request.port)

            if requested_port not in _ports:
                raise ValueError(f"port {requested_port} not opened")

            logger.info(f'closing isolated port: {request.port}')

            close_step_1_result = subprocess.check_output([
                'nft', 'delete', 'rule', 'inet', 'filter', 'pirogue_admin_chain',
                'handle', _ports[requested_port]['handle_iif']])

            close_step_2_result = subprocess.check_output([
                'nft', 'delete', 'rule', 'inet', 'filter', 'pirogue_admin_chain',
                'handle', _ports[requested_port]['handle_oif']])

        else:
            logger.info(f'closing all isolated ports')

            close_result = subprocess.check_output([
                'nft', 'flush', 'chain', 'inet', 'filter', 'pirogue_admin_chain'])

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


class AccessServicerImpl(access_pb2_grpc.AccessServicer):

    _user_accesses : UserAccessRegistry

    """
    Provides implementation for PiRogue admin Access service.
    """
    def __init__(self,
                 base_configuration_context: ConfigurationContext,
                 get_port_func: Callable[[], int],
                 get_token_func: Callable[[], str],
                 reset_token_func: Callable[[], None],
                 user_accesses: UserAccessRegistry):
        self._base_configuration_context = base_configuration_context
        self._get_port_func = get_port_func
        self._get_token_func = get_token_func
        self._reset_token_func = reset_token_func
        self._user_accesses = user_accesses

    def register_to_server(self, server):
        access_pb2_grpc.add_AccessServicer_to_server(self, server)

    @property
    def _pcl(self) -> PackageConfigLoader:
        return PackageConfigLoader(self._base_configuration_context)

    def ResetAdministrationToken(self, request, context):

        logger.info('reset-ing administration token')

        self._reset_token_func()
        return StringValue(value=self._get_token_func())

    def GetAdministrationToken(self, request, context):
        return StringValue(value=self._get_token_func())

    def GetAdministrationCertificate(self, request, context):
        certificate_fullpath = Path(self._base_configuration_context.var_dir, ADMIN_SELF_SIGNED_CERTIFICATE_PATH)
        certificate = Path(certificate_fullpath).read_text()
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

    @staticmethod
    def _user_access_to_grpc(user_access: UserAccess_Internal):
        services = {}
        for (service, methods) in user_access.permissions.items():
            services[service] = MethodAccess()
            for method in methods:
                services[service].permission.append(method)
        permissions = ServiceAccess(services=services)
        response = UserAccess(idx=user_access.idx, token=user_access.token, permissions=permissions)
        return response

    def CreateUserAccess(self, request, context):
        user_access = self._user_accesses.create()
        response = AccessServicerImpl._user_access_to_grpc(user_access)
        return response

    def GetUserAccess(self, request, context):
        idx = request.value
        try:
            user_access = self._user_accesses.get(idx)
            response = AccessServicerImpl._user_access_to_grpc(user_access)
            return response
        except KeyError:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"UserAccess not found idx:{idx}")
            return UserAccess()

    def ListUserAccesses(self, request, context):
        response = UserAccessList()
        for user_access in self._user_accesses._user_accesses:
            response.user_accesses.append(AccessServicerImpl._user_access_to_grpc(user_access))
        return response

    def DeleteUserAccess(self, request, context):
        idx = request.value
        try:
            self._user_accesses.delete(idx)
        except KeyError:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"UserAccess not found idx:{idx}")
        return EMPTY

    def ResetUserAccessToken(self, request, context):
        idx = request.value
        try:
            user_access = self._user_accesses.reset_token(idx)
            response = AccessServicerImpl._user_access_to_grpc(user_access)
            return response
        except KeyError:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"UserAccess not found idx:{idx}")
            return UserAccess()

    def GetPermissionList(self, request, context):
        permissions_map = {}
        for (service_name, methods) in self._user_accesses.available_permissions.items():
            permissions_map[service_name] = MethodAccess()
            for method_name in methods:
                permissions_map[service_name].permission.append(method_name)
        response = ServiceAccess(services=permissions_map)
        return response

    def SetUserAccessPermissions(self, request, context):
        idx = request.user_access_idx

        sets: Dict[str, Set[str]] = {}
        adds: Dict[str, Set[str]] = {}
        removes: Dict[str, Set[str]] = {}

        has_sets = False
        has_adds = False
        has_removes = False

        try:
            for (service, method_access) in request.sets.services.items():
                for permission in method_access.permission:
                    self._user_accesses.check_permission(service, permission)
                    sets.setdefault(service, set()).add(permission)
                    has_sets = True
            for (service, method_access) in request.adds.services.items():
                for permission in method_access.permission:
                    adds.setdefault(service, set()).add(permission)
                    has_adds = True
            for (service, method_access) in request.removes.services.items():
                for permission in method_access.permission:
                    removes.setdefault(service, set()).add(permission)
                    has_removes = True
        except IllegalPermissionError as error:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(f"Permission not found: {error.permission}")
            return UserAccess()

        if has_sets and (has_adds or has_removes):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(f"Can't add or remove permissions with 'sets' permissions is defined")
            return UserAccess()

        try:
            user_access = self._user_accesses.set_permissions(idx, sets, adds, removes)
            response = AccessServicerImpl._user_access_to_grpc(user_access)
            return response
        except KeyError:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"UserAccess not found idx:{idx}")
            return UserAccess()
