from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import wrappers_pb2 as _wrappers_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DashboardConfiguration(_message.Message):
    __slots__ = ["password"]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    password: str
    def __init__(self, password: _Optional[str] = ...) -> None: ...

class SuricataRulesSource(_message.Message):
    __slots__ = ["name", "url"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    name: str
    url: str
    def __init__(self, name: _Optional[str] = ..., url: _Optional[str] = ...) -> None: ...

class SuricataRulesSources(_message.Message):
    __slots__ = ["sources"]
    SOURCES_FIELD_NUMBER: _ClassVar[int]
    sources: _containers.RepeatedCompositeFieldContainer[SuricataRulesSource]
    def __init__(self, sources: _Optional[_Iterable[_Union[SuricataRulesSource, _Mapping]]] = ...) -> None: ...
