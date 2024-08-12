# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pirogue_admin_api/network.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2
from google.protobuf import wrappers_pb2 as google_dot_protobuf_dot_wrappers__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1fpirogue_admin_api/network.proto\x12\x15pirogue.admin.network\x1a\x1bgoogle/protobuf/empty.proto\x1a\x1egoogle/protobuf/wrappers.proto\"e\n\x07VPNPeer\x12\x0b\n\x03idx\x18\x01 \x01(\x05\x12\x0f\n\x07\x63omment\x18\x02 \x01(\t\x12\x12\n\npublic_key\x18\x03 \x01(\t\x12\x18\n\x0bprivate_key\x18\x04 \x01(\tH\x00\x88\x01\x01\x42\x0e\n\x0c_private_key\"]\n\x11VPNPeerAddRequest\x12\x14\n\x07\x63omment\x18\x01 \x01(\tH\x00\x88\x01\x01\x12\x17\n\npublic_key\x18\x02 \x01(\tH\x01\x88\x01\x01\x42\n\n\x08_commentB\r\n\x0b_public_key\"<\n\x0bVPNPeerList\x12-\n\x05peers\x18\x01 \x03(\x0b\x32\x1e.pirogue.admin.network.VPNPeer\"\x83\x01\n\x11WifiConfiguration\x12\x11\n\x04ssid\x18\x01 \x01(\tH\x00\x88\x01\x01\x12\x17\n\npassphrase\x18\x02 \x01(\tH\x01\x88\x01\x01\x12\x19\n\x0c\x63ountry_code\x18\x03 \x01(\tH\x02\x88\x01\x01\x42\x07\n\x05_ssidB\r\n\x0b_passphraseB\x0f\n\r_country_code\"4\n\x13PublicAccessRequest\x12\x0e\n\x06\x64omain\x18\x01 \x01(\t\x12\r\n\x05\x65mail\x18\x02 \x01(\t\"P\n\x0cIsolatedPort\x12\x0c\n\x04port\x18\x01 \x01(\r\x12\x1d\n\x10\x64\x65stination_port\x18\x02 \x01(\rH\x00\x88\x01\x01\x42\x13\n\x11_destination_port\"F\n\x10IsolatedPortList\x12\x32\n\x05ports\x18\x01 \x03(\x0b\x32#.pirogue.admin.network.IsolatedPort2\xc6\n\n\x07Network\x12L\n\x0cListVPNPeers\x12\x16.google.protobuf.Empty\x1a\".pirogue.admin.network.VPNPeerList\"\x00\x12K\n\nGetVPNPeer\x12\x1b.google.protobuf.Int32Value\x1a\x1e.pirogue.admin.network.VPNPeer\"\x00\x12O\n\x10GetVPNPeerConfig\x12\x1b.google.protobuf.Int32Value\x1a\x1c.google.protobuf.StringValue\"\x00\x12X\n\nAddVPNPeer\x12(.pirogue.admin.network.VPNPeerAddRequest\x1a\x1e.pirogue.admin.network.VPNPeer\"\x00\x12N\n\rDeleteVPNPeer\x12\x1b.google.protobuf.Int32Value\x1a\x1e.pirogue.admin.network.VPNPeer\"\x00\x12Z\n\x14GetWifiConfiguration\x12\x16.google.protobuf.Empty\x1a(.pirogue.admin.network.WifiConfiguration\"\x00\x12Z\n\x14SetWifiConfiguration\x12(.pirogue.admin.network.WifiConfiguration\x1a\x16.google.protobuf.Empty\"\x00\x12R\n\x18ResetAdministrationToken\x12\x16.google.protobuf.Empty\x1a\x1c.google.protobuf.StringValue\"\x00\x12P\n\x16GetAdministrationToken\x12\x16.google.protobuf.Empty\x1a\x1c.google.protobuf.StringValue\"\x00\x12V\n\x1cGetAdministrationCertificate\x12\x16.google.protobuf.Empty\x1a\x1c.google.protobuf.StringValue\"\x00\x12O\n\x15GetAdministrationCLIs\x12\x16.google.protobuf.Empty\x1a\x1c.google.protobuf.StringValue\"\x00\x12\x62\n\x1a\x45nableExternalPublicAccess\x12*.pirogue.admin.network.PublicAccessRequest\x1a\x16.google.protobuf.Empty\"\x00\x12O\n\x1b\x44isableExternalPublicAccess\x12\x16.google.protobuf.Empty\x1a\x16.google.protobuf.Empty\"\x00\x12Q\n\x10OpenIsolatedPort\x12#.pirogue.admin.network.IsolatedPort\x1a\x16.google.protobuf.Empty\"\x00\x12K\n\x11\x43loseIsolatedPort\x12\x1c.google.protobuf.UInt32Value\x1a\x16.google.protobuf.Empty\"\x00\x12I\n\x15ListIsolatedOpenPorts\x12\x16.google.protobuf.Empty\x1a\x16.google.protobuf.Empty\"\x00\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'pirogue_admin_api.network_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _VPNPEER._serialized_start=119
  _VPNPEER._serialized_end=220
  _VPNPEERADDREQUEST._serialized_start=222
  _VPNPEERADDREQUEST._serialized_end=315
  _VPNPEERLIST._serialized_start=317
  _VPNPEERLIST._serialized_end=377
  _WIFICONFIGURATION._serialized_start=380
  _WIFICONFIGURATION._serialized_end=511
  _PUBLICACCESSREQUEST._serialized_start=513
  _PUBLICACCESSREQUEST._serialized_end=565
  _ISOLATEDPORT._serialized_start=567
  _ISOLATEDPORT._serialized_end=647
  _ISOLATEDPORTLIST._serialized_start=649
  _ISOLATEDPORTLIST._serialized_end=719
  _NETWORK._serialized_start=722
  _NETWORK._serialized_end=2072
# @@protoc_insertion_point(module_scope)
