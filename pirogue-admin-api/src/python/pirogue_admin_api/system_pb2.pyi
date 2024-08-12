from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import wrappers_pb2 as _wrappers_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor
OPERATING_MODE_ACCESS_POINT: OperatingMode
OPERATING_MODE_APPLIANCE: OperatingMode
OPERATING_MODE_UNSPECIFIED: OperatingMode
OPERATING_MODE_VPN: OperatingMode
OPERATING_MODE_WIFI_2_USB_TETHERING: OperatingMode
STATUS_STATE_DOWN: StatusState
STATUS_STATE_ERROR: StatusState
STATUS_STATE_STARTING: StatusState
STATUS_STATE_STOPPING: StatusState
STATUS_STATE_UNSPECIFIED: StatusState
STATUS_STATE_UP: StatusState

class ApplyRequest(_message.Message):
    __slots__ = ["commit", "configuration", "from_scratch"]
    COMMIT_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    FROM_SCRATCH_FIELD_NUMBER: _ClassVar[int]
    commit: bool
    configuration: Configuration
    from_scratch: bool
    def __init__(self, configuration: _Optional[_Union[Configuration, _Mapping]] = ..., commit: bool = ..., from_scratch: bool = ...) -> None: ...

class Configuration(_message.Message):
    __slots__ = ["variables"]
    class VariablesEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    VARIABLES_FIELD_NUMBER: _ClassVar[int]
    variables: _containers.ScalarMap[str, str]
    def __init__(self, variables: _Optional[_Mapping[str, str]] = ...) -> None: ...

class ConfigurationTree(_message.Message):
    __slots__ = ["actions", "files", "packages", "variables"]
    class ActionsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ConfigurationTreeSection
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ConfigurationTreeSection, _Mapping]] = ...) -> None: ...
    class FilesEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ConfigurationTreeSection
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ConfigurationTreeSection, _Mapping]] = ...) -> None: ...
    class PackagesEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ConfigurationTreeSection
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ConfigurationTreeSection, _Mapping]] = ...) -> None: ...
    class VariablesEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ConfigurationTreeSection
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ConfigurationTreeSection, _Mapping]] = ...) -> None: ...
    ACTIONS_FIELD_NUMBER: _ClassVar[int]
    FILES_FIELD_NUMBER: _ClassVar[int]
    PACKAGES_FIELD_NUMBER: _ClassVar[int]
    VARIABLES_FIELD_NUMBER: _ClassVar[int]
    actions: _containers.MessageMap[str, ConfigurationTreeSection]
    files: _containers.MessageMap[str, ConfigurationTreeSection]
    packages: _containers.MessageMap[str, ConfigurationTreeSection]
    variables: _containers.MessageMap[str, ConfigurationTreeSection]
    def __init__(self, packages: _Optional[_Mapping[str, ConfigurationTreeSection]] = ..., files: _Optional[_Mapping[str, ConfigurationTreeSection]] = ..., variables: _Optional[_Mapping[str, ConfigurationTreeSection]] = ..., actions: _Optional[_Mapping[str, ConfigurationTreeSection]] = ...) -> None: ...

class ConfigurationTreeSection(_message.Message):
    __slots__ = ["actions", "default", "files", "packages", "variables"]
    ACTIONS_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_FIELD_NUMBER: _ClassVar[int]
    FILES_FIELD_NUMBER: _ClassVar[int]
    PACKAGES_FIELD_NUMBER: _ClassVar[int]
    VARIABLES_FIELD_NUMBER: _ClassVar[int]
    actions: _containers.RepeatedScalarFieldContainer[str]
    default: str
    files: _containers.RepeatedScalarFieldContainer[str]
    packages: _containers.RepeatedScalarFieldContainer[str]
    variables: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, packages: _Optional[_Iterable[str]] = ..., files: _Optional[_Iterable[str]] = ..., variables: _Optional[_Iterable[str]] = ..., actions: _Optional[_Iterable[str]] = ..., default: _Optional[str] = ...) -> None: ...

class Device(_message.Message):
    __slots__ = ["name"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class DeviceList(_message.Message):
    __slots__ = ["devices"]
    DEVICES_FIELD_NUMBER: _ClassVar[int]
    devices: _containers.RepeatedCompositeFieldContainer[Device]
    def __init__(self, devices: _Optional[_Iterable[_Union[Device, _Mapping]]] = ...) -> None: ...

class OperatingModeResponse(_message.Message):
    __slots__ = ["mode"]
    MODE_FIELD_NUMBER: _ClassVar[int]
    mode: OperatingMode
    def __init__(self, mode: _Optional[_Union[OperatingMode, str]] = ...) -> None: ...

class PackageInfo(_message.Message):
    __slots__ = ["name", "status", "version"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    name: str
    status: str
    version: str
    def __init__(self, name: _Optional[str] = ..., version: _Optional[str] = ..., status: _Optional[str] = ...) -> None: ...

class PackagesInfo(_message.Message):
    __slots__ = ["packages"]
    PACKAGES_FIELD_NUMBER: _ClassVar[int]
    packages: _containers.RepeatedCompositeFieldContainer[PackageInfo]
    def __init__(self, packages: _Optional[_Iterable[_Union[PackageInfo, _Mapping]]] = ...) -> None: ...

class Status(_message.Message):
    __slots__ = ["status"]
    class StatusEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: StatusState
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[StatusState, str]] = ...) -> None: ...
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: _containers.ScalarMap[str, StatusState]
    def __init__(self, status: _Optional[_Mapping[str, StatusState]] = ...) -> None: ...

class OperatingMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class StatusState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
