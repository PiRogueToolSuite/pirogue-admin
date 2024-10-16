from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import wrappers_pb2 as _wrappers_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ClosePortRequest(_message.Message):
    __slots__ = ["port"]
    PORT_FIELD_NUMBER: _ClassVar[int]
    port: int
    def __init__(self, port: _Optional[int] = ...) -> None: ...

class IsolatedPort(_message.Message):
    __slots__ = ["destination_port", "port"]
    DESTINATION_PORT_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    destination_port: int
    port: int
    def __init__(self, port: _Optional[int] = ..., destination_port: _Optional[int] = ...) -> None: ...

class IsolatedPortList(_message.Message):
    __slots__ = ["ports"]
    PORTS_FIELD_NUMBER: _ClassVar[int]
    ports: _containers.RepeatedCompositeFieldContainer[IsolatedPort]
    def __init__(self, ports: _Optional[_Iterable[_Union[IsolatedPort, _Mapping]]] = ...) -> None: ...

class PublicAccessRequest(_message.Message):
    __slots__ = ["domain", "email"]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    domain: str
    email: str
    def __init__(self, domain: _Optional[str] = ..., email: _Optional[str] = ...) -> None: ...

class VPNPeer(_message.Message):
    __slots__ = ["comment", "idx", "private_key", "public_key"]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    IDX_FIELD_NUMBER: _ClassVar[int]
    PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    comment: str
    idx: int
    private_key: str
    public_key: str
    def __init__(self, idx: _Optional[int] = ..., comment: _Optional[str] = ..., public_key: _Optional[str] = ..., private_key: _Optional[str] = ...) -> None: ...

class VPNPeerAddRequest(_message.Message):
    __slots__ = ["comment", "public_key"]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    comment: str
    public_key: str
    def __init__(self, comment: _Optional[str] = ..., public_key: _Optional[str] = ...) -> None: ...

class VPNPeerList(_message.Message):
    __slots__ = ["peers"]
    PEERS_FIELD_NUMBER: _ClassVar[int]
    peers: _containers.RepeatedCompositeFieldContainer[VPNPeer]
    def __init__(self, peers: _Optional[_Iterable[_Union[VPNPeer, _Mapping]]] = ...) -> None: ...

class WifiConfiguration(_message.Message):
    __slots__ = ["country_code", "passphrase", "ssid"]
    COUNTRY_CODE_FIELD_NUMBER: _ClassVar[int]
    PASSPHRASE_FIELD_NUMBER: _ClassVar[int]
    SSID_FIELD_NUMBER: _ClassVar[int]
    country_code: str
    passphrase: str
    ssid: str
    def __init__(self, ssid: _Optional[str] = ..., passphrase: _Optional[str] = ..., country_code: _Optional[str] = ...) -> None: ...
