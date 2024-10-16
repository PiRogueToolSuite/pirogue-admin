import functools
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable

import grpc
import yaml
from google.protobuf import empty_pb2
from google.protobuf.json_format import MessageToDict, ParseDict
from google.protobuf.wrappers_pb2 import Int32Value, UInt32Value, StringValue

from pirogue_admin_api import system_pb2, system_pb2_grpc
from pirogue_admin_api import services_pb2, services_pb2_grpc
from pirogue_admin_api import network_pb2, network_pb2_grpc

from pirogue_admin_api import (
    PIROGUE_ADMIN_AUTH_HEADER, PIROGUE_ADMIN_AUTH_SCHEME,
    PIROGUE_ADMIN_TCP_PORT)
from pirogue_admin_api.network_pb2 import WifiConfiguration, VPNPeerAddRequest, ClosePortRequest, IsolatedPort, PublicAccessRequest
from pirogue_admin_api.services_pb2 import DashboardConfiguration, SuricataRulesSource
from pirogue_admin_client.types import OperatingMode

EMPTY = empty_pb2.Empty()


class NoPiRogueAdminConnection(BaseException):
    """"""


class ApplyConfigurationError(BaseException):
    """"""


def _inject_token_request(callback: grpc.AuthMetadataPluginCallback,
                          token: Optional[str], error: Optional[Exception]):
    metadata = ((PIROGUE_ADMIN_AUTH_HEADER, '%s %s' % (PIROGUE_ADMIN_AUTH_SCHEME, token)),)
    callback(metadata, error)


class TokenAuthMetadataPlugin(grpc.AuthMetadataPlugin):
    """Metadata wrapper for raw access token credentials."""
    _token: str

    def __init__(self, access_token: str):
        self._token = access_token

    def __call__(self, context: grpc.AuthMetadataContext,
                 callback: grpc.AuthMetadataPluginCallback):
        _inject_token_request(callback, self._token, None)


def access_token_call_credentials(access_token):
    """Construct CallCredentials from an access token.

    Args:
      access_token: A string to place directly in the http request
        authorization header, for example
        "authorization: Token <access_token>".

    Returns:
      A CallCredentials.
    """
    return grpc.metadata_call_credentials(
        TokenAuthMetadataPlugin(access_token), None)


class BaseAdapter:

    def __init__(self, channel):
        pass


class SystemAdapter(BaseAdapter):
    _stub_system: system_pb2_grpc.SystemStub

    def __init__(self, channel):
        super(SystemAdapter, self).__init__(channel)
        self._stub_system = system_pb2_grpc.SystemStub(channel)

    def get_configuration_tree(self):
        answer = self._stub_system.GetConfigurationTree(EMPTY)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        return answer

    def get_configuration(self):
        answer = self._stub_system.GetConfiguration(EMPTY)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        if 'variables' in answer:
            answer = answer['variables']
        return answer

    def get_operating_mode(self):
        answer = self._stub_system.GetOperatingMode(EMPTY)
        return OperatingMode(answer.mode)

    def get_status(self):
        answer = self._stub_system.GetStatus(EMPTY)
        answer = MessageToDict(answer)
        return answer

    def get_packages_info(self):
        answer = self._stub_system.GetPackagesInfo(EMPTY)
        answer = MessageToDict(answer)
        return answer

    def get_hostname(self):
        answer = self._stub_system.GetHostname(EMPTY)
        answer = MessageToDict(answer)
        return answer

    def set_hostname(self, hostname: str):
        answer = self._stub_system.SetHostname(StringValue(value=hostname))

    def get_locale(self):
        answer = self._stub_system.GetLocale(EMPTY)
        answer = MessageToDict(answer)
        return answer

    def set_locale(self, locale: str):
        answer = self._stub_system.SetLocale(StringValue(value=locale))

    def get_timezone(self):
        answer = self._stub_system.GetTimezone(EMPTY)
        answer = MessageToDict(answer)
        return answer

    def set_timezone(self, timezone: str):
        answer = self._stub_system.SetTimezone(StringValue(value=timezone))

    def list_connected_devices(self):
        answer = self._stub_system.ListConnectedDevices(EMPTY)
        answer = MessageToDict(answer)
        return answer


class NetworkAdapter(BaseAdapter):
    _stub_network: network_pb2_grpc.NetworkStub

    def __init__(self, channel):
        super(NetworkAdapter, self).__init__(channel)
        self._stub_network = network_pb2_grpc.NetworkStub(channel)

    def get_wifi_configuration(self):
        answer = self._stub_network.GetWifiConfiguration(EMPTY)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        return answer

    def set_wifi_configuration(self, ssid: str = None, passphrase: str = None, country_code: str = None):
        if ssid is None and passphrase is None and country_code is None:
            raise ValueError('please provide at least one of ssid, passphrase or country_code')
        message = WifiConfiguration()
        if ssid:
            message.ssid = ssid
        if passphrase:
            message.passphrase = passphrase
        if country_code:
            message.country_code = country_code
        logging.debug(f'set_wifi_configuration({message})')
        answer = self._stub_network.SetWifiConfiguration(message)

    def list_vpn_peers(self):
        answer = self._stub_network.ListVPNPeers(EMPTY)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        if 'peers' in answer:
            answer = answer['peers']
        return answer

    def get_vpn_peer(self, idx: int):
        idx_param = Int32Value()
        idx_param.value = int(idx)
        answer = self._stub_network.GetVPNPeer(idx_param)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        return answer

    def get_vpn_peer_config(self, idx: int):
        idx_param = Int32Value()
        idx_param.value = int(idx)
        answer = self._stub_network.GetVPNPeerConfig(idx_param)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        return answer

    def add_vpn_peer(self, comment: str = None, public_key: str = None):
        add_request = VPNPeerAddRequest(comment=comment, public_key=public_key)
        answer = self._stub_network.AddVPNPeer(add_request)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        return answer

    def delete_vpn_peer(self, idx: int):
        idx_param = Int32Value()
        idx_param.value = int(idx)
        answer = self._stub_network.DeleteVPNPeer(idx_param)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        return answer

    def reset_administration_token(self):
        answer = self._stub_network.ResetAdministrationToken(EMPTY)
        answer = MessageToDict(answer)
        return answer

    def get_administration_token(self):
        answer = self._stub_network.GetAdministrationToken(EMPTY)
        answer = MessageToDict(answer)
        return answer

    def get_administration_certificate(self):
        answer = self._stub_network.GetAdministrationCertificate(EMPTY)
        answer = MessageToDict(answer)
        return answer

    def get_administration_clis(self):
        answer = self._stub_network.GetAdministrationCLIs(EMPTY)
        answer = MessageToDict(answer)
        return answer

    def enable_external_public_access(self, domain: str, email: str):
        request = PublicAccessRequest(domain=domain, email=email)
        answer = self._stub_network.EnableExternalPublicAccess(request)

    def disable_external_public_access(self):
        answer = self._stub_network.DisableExternalPublicAccess(EMPTY)

    def list_isolated_open_ports(self):
        answer = self._stub_network.ListIsolatedOpenPorts(EMPTY)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        if 'ports' in answer:
            answer = answer['ports']
        return answer

    def open_isolated_port(self, incoming_port: int, outgoing_port: int = None):
        request = IsolatedPort(port=int(incoming_port))
        if outgoing_port:
            request.destination_port = int(outgoing_port)
        answer = self._stub_network.OpenIsolatedPort(request)

    def close_isolated_port(self, incoming_port: int = None):
        request = ClosePortRequest()
        if incoming_port:
            request.port = int(incoming_port)
        answer = self._stub_network.CloseIsolatedPort(request)


class ServicesAdapter(BaseAdapter):
    _stub_services: services_pb2_grpc.ServicesStub

    def __init__(self, channel):
        super(ServicesAdapter, self).__init__(channel)
        self._stub_services = services_pb2_grpc.ServicesStub(channel)

    def set_dashboard_configuration(self, password: str):
        request = DashboardConfiguration(password=password)
        answer = self._stub_services.SetDashboardConfiguration(request)

    def get_dashboard_configuration(self):
        answer = self._stub_services.GetDashboardConfiguration(EMPTY)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        return answer

    def list_suricata_rules_sources(self):
        answer = self._stub_services.ListSuricataRulesSources(EMPTY)
        answer = MessageToDict(answer, preserving_proto_field_name=True)
        if 'sources' in answer:
            answer = answer['sources']
        return answer

    def add_suricata_rules_source(self, name: str, url: str):
        add_request = SuricataRulesSource(name=name, url=url)
        answer = self._stub_services.AddSuricataRulesSource(add_request)

    def delete_suricata_rules_source(self, name: str):
        answer = self._stub_services.DeleteSuricataRulesSource(StringValue(value=name))
