import logging
import secrets
from dataclasses import dataclass, field, asdict

import yaml
from pathlib import Path

from pirogue_admin.package_config import ConfigurationContext
from typing import Dict,List,Set

from pirogue_admin_api.network_pb2 import DESCRIPTOR as DESCRIPTOR_NETWORK
from pirogue_admin_api.services_pb2 import DESCRIPTOR as DESCRIPTOR_SERVICES
from pirogue_admin_api.system_pb2 import DESCRIPTOR as DESCRIPTOR_SYSTEM
from pirogue_admin_api.access_pb2 import DESCRIPTOR as DESCRIPTOR_ACCESS

ADMIN_USER_ACCESSES_REGISTRY_PATH = 'user_accesses.yaml'

ALL_SERVICE_PERMISSION = 'all'

logger = logging.getLogger(__name__)

class IllegalPermissionError(ValueError):
    permission: str
    def __init__(self, permission):
        self.permission = permission


def list_methods_by_services_for_descriptor(domain_descriptor):
    """
    One DESCRIPTOR may contain more than one service. Each service contains many methods.
    """
    permissions_map = {}
    for (service_name, service) in  domain_descriptor.services_by_name.items():
        permissions_map[service.full_name] = set()
        for method in service.methods:
            permissions_map[service.full_name].add(method.name)
    return permissions_map


def service_short_name(service_full_name):
    return service_full_name.split('.')[-1]


@dataclass
class UserAccess:
    idx: int
    token: str
    permissions: Dict[str, Set[str]] = field(default_factory=dict)


class UserAccessRegistry:

    _ctx: ConfigurationContext
    _user_accesses: List[UserAccess] = []
    _services_short_name_to_long_name: Dict[str, str] = {}
    available_permissions: Dict[str, Set[str]] = {}
    _current_access_tree: Dict[str, Set[str]] = {}

    def __init__(self, ctx: ConfigurationContext):
        self._ctx = ctx

        self._scan_permissions()
        self._load_or_create()

    @property
    def registry_path(self):
        return Path(self._ctx.var_dir, ADMIN_USER_ACCESSES_REGISTRY_PATH)

    def _scan_permissions(self):
        """Scans available permissions from all current grpc servicers"""
        methods_map_by_service = {}
        methods_map_by_service |= list_methods_by_services_for_descriptor(DESCRIPTOR_SYSTEM)
        methods_map_by_service |= list_methods_by_services_for_descriptor(DESCRIPTOR_SERVICES)
        methods_map_by_service |= list_methods_by_services_for_descriptor(DESCRIPTOR_NETWORK)
        # TODO: decide if we need to authorize non administrator access
        #  to manage (own?) permissions through 'Access' service
        #  methods_map_by_service |= list_methods_by_services_for_descriptor(DESCRIPTOR_ACCESS)
        permissions_map_with_short_service_name_as_key = dict(map(
            lambda kv: (service_short_name(kv[0]),kv[1]),
            methods_map_by_service.items()))
        self._services_short_name_to_long_name = dict(map(
            lambda k: (service_short_name(k),k), methods_map_by_service.keys()
        ))
        self.available_permissions = permissions_map_with_short_service_name_as_key

    def _clean_or_migrate_permissions(self, user_accesses):
        """Migrates old permissions contained in given user_accesses to available ones"""
        was_dirty = False
        for (user_access) in user_accesses:
            clean_permissions = {}
            for (service, permissions) in user_access.permissions.items():
                if service not in self.available_permissions:
                    logger.warning(f"Service '{service}' not an available permissions for user idx:{user_access.idx}: ignoring")
                    was_dirty = True
                    continue
                for permission in permissions:
                    if permission not in self.available_permissions[service]:
                        logger.warning(f"Permission '{service}:{permission}' not in available permissions for user idx:{user_access.idx}: ignoring")
                        was_dirty = True
                        continue
                    clean_permissions.setdefault(service, set()).add(permission)
            user_access.permissions = clean_permissions
        return was_dirty

    def _rebuild_access_tree(self):
        new_access_tree = {}
        for user_access in self._user_accesses:
            for (service, permissions) in user_access.permissions.items():
                for permission in permissions:
                    rpc_call = f"/{self._services_short_name_to_long_name[service]}/{permission}"
                    new_access_tree.setdefault(rpc_call, set()).add(user_access.token)
        self._current_access_tree = new_access_tree

    def _save(self):
        logger.info("Writing user accesses registry: %s", self.registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        user_accesses_as_dict = [asdict(user_access) for user_access in self._user_accesses]
        with open(self.registry_path, 'w', encoding="utf-8") as out_fd:
            yaml.safe_dump(stream=out_fd,
                           sort_keys=False,
                           default_flow_style=False,
                           encoding="utf-8",
                           allow_unicode=True,
                           data=user_accesses_as_dict)
        self._rebuild_access_tree()

    def _load_or_create(self):
        if not self.registry_path.exists():
            logger.info("Creating user accesses registry: %s", self.registry_path)
            self._save()
        else:
            logger.info("Loading user accesses registry: %s", self.registry_path)
        loaded_user_accesses = yaml.safe_load(self.registry_path.read_text())
        remapped_user_accesses: List[UserAccess] = [UserAccess(**user_access) for user_access in loaded_user_accesses]
        was_dirty = self._clean_or_migrate_permissions(remapped_user_accesses)
        self._user_accesses = remapped_user_accesses
        self._rebuild_access_tree()
        if was_dirty:
            self._save()

    def has_access(self, method, token):
        if method not in self._current_access_tree:
            return False
        return token in self._current_access_tree[method]

    def _next_available_idx(self):
        used_indices = [c.idx for c in self._user_accesses]
        used_indices.sort()
        # For-shadowing: Starting indices at '1' instead of '0'
        # is needed to force marshalling of the integer field  'idx'
        # during GRPC exchanges.
        # Reason: default field value depending on its type are not
        # marshaled, this is by design for compression optimization
        available_idx = 1
        while available_idx in used_indices:
            available_idx += 1
        return available_idx

    def create(self):
        new_idx = self._next_available_idx()
        new_token = UserAccessRegistry._generate_token()
        new_ua = UserAccess(idx=new_idx, token=new_token)
        self._user_accesses.append(new_ua)
        self._save()
        return new_ua

    def get(self, idx:int):
        for ua in self._user_accesses:
            if ua.idx == idx:
                return ua
        raise KeyError(idx)

    def reset_token(self, idx:int):
        user_access = None
        for ua in self._user_accesses:
            if ua.idx == idx:
                user_access = ua
                break
        if user_access is None:
            raise KeyError(idx)
        user_access.token = UserAccessRegistry._generate_token()
        self._save()
        return user_access

    def set_permissions(self, idx:int,
                        sets:Dict[str,Set[str]] = None,
                        adds:Dict[str,Set[str]] = None,
                        removes:Dict[str,Set[str]] = None):
        user_access = None
        for ua in self._user_accesses:
            if ua.idx == idx:
                user_access = ua
                break
        if user_access is None:
            raise KeyError(idx)

        new_permissions = user_access.permissions

        if len(sets) > 0:
            new_permissions = {}
            # Will ignore adds and removes
            for (service, permissions) in sets.items():
                for permission in permissions:
                    logger.debug('set permission %s:%s', service, permission)
                    if permission == ALL_SERVICE_PERMISSION:
                        new_permissions[service] = self.available_permissions[service].copy()
                        break
                    new_permissions.setdefault(service, set()).add(permission)
        else:
            for (service, permissions) in adds.items():
                for permission in permissions:
                    logger.debug('add permission %s:%s', service, permission)
                    if permission == ALL_SERVICE_PERMISSION:
                        new_permissions[service] = self.available_permissions[service].copy()
                        break
                    new_permissions.setdefault(service, set()).add(permission)
            for (service, permissions) in removes.items():
                for permission in permissions:
                    logger.debug('remove permission %s:%s', service, permission)
                    if permission == ALL_SERVICE_PERMISSION:
                        new_permissions.pop(service, None)
                        break
                    try:
                        new_permissions.setdefault(service, set()).remove(permission)
                    except ValueError:
                        pass
                    if len(new_permissions[service]) == 0:
                        new_permissions.pop(service, None)
        user_access.permissions = new_permissions
        self._save()
        return user_access

    def delete(self, idx:int):
        user_access = None
        for ua in self._user_accesses:
            if ua.idx == idx:
                user_access = ua
                break
        if user_access is None:
            raise KeyError(idx)
        self._user_accesses.remove(user_access)
        self._save()

    def check_permission(self, service, permission):
        if service not in self.available_permissions:
            raise IllegalPermissionError(f"{service}:{permission}")
        if permission == ALL_SERVICE_PERMISSION:
            return True
        if permission not in self.available_permissions[service]:
            raise IllegalPermissionError(f"{service}:{permission}")

    @staticmethod
    def _generate_token():
        return secrets.token_urlsafe(64)