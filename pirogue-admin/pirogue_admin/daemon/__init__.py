import argparse
import grpc
import logging
import os
import pystemd.daemon
import re
import secrets
import yaml

from typing import Callable

from concurrent import futures
from pathlib import Path

from pirogue_admin.package_config import ConfigurationContext

from pirogue_admin_api import (
    PIROGUE_ADMIN_AUTH_HEADER, PIROGUE_ADMIN_AUTH_SCHEME,
    PIROGUE_ADMIN_TCP_PORT)

from .user_access import UserAccessRegistry
from .servicers_impl import (
    SystemServicerImpl,
    NetworkServicerImpl,
    ServicesServicerImpl,
    AccessServicerImpl,
)

WORKING_ROOT_DIR = '/'
ADMIN_CONFIG_DIR = '/usr/share/pirogue-admin'
ADMIN_VAR_DIR = '/var/lib/pirogue/admin'

logger = logging.getLogger('pirogue-admin-daemon')


class TokenValidationInterceptor(grpc.ServerInterceptor):
    _resolve_token = Callable[[], str]
    _user_accesses : UserAccessRegistry

    def __init__(self, token_resolver: Callable[[], str], user_accesses: UserAccessRegistry):
        self._resolve_token = token_resolver
        self._user_accesses = user_accesses
        self._token_expression = re.escape(PIROGUE_ADMIN_AUTH_SCHEME) + r" ([^\s,]+)"

        def abort(ignored_request, context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid token")

        def unauthorized(ignored_request, context):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Permission denied")

        self._abort_handler = grpc.unary_unary_rpc_method_handler(abort)
        self._unauthorized_handler = grpc.unary_unary_rpc_method_handler(unauthorized)

    def intercept_service(self, continuation, handler_call_details):
        admin_token = self._resolve_token()
        expected_admin_metadata = (PIROGUE_ADMIN_AUTH_HEADER, "%s %s" % (PIROGUE_ADMIN_AUTH_SCHEME, admin_token))
        target_method = handler_call_details.method

        if expected_admin_metadata in handler_call_details.invocation_metadata:
            # If 'admin' token, continue regardless of the service/method called
            logger.debug("Calling %s as administrator", target_method)
            return continuation(handler_call_details)

        # Extract toekn for user access check
        metadata = dict(handler_call_details.invocation_metadata)
        if PIROGUE_ADMIN_AUTH_HEADER not in metadata:
            return self._abort_handler
        authoization = metadata.get(PIROGUE_ADMIN_AUTH_HEADER)
        auth_match = re.search(self._token_expression, authoization)
        if not auth_match:
            return self._abort_handler
        auth_token = auth_match.group(1)

        #
        if self._user_accesses.has_access(target_method, auth_token):
            # Check if
            logger.debug("Calling %s with auth token %s", target_method, auth_token)
            return continuation(handler_call_details)
        else:
            return self._unauthorized_handler


class PiRogueAdminDaemon:
    _base_context: ConfigurationContext
    _port: int
    _token: str
    _user_accesses: UserAccessRegistry

    def __init__(self, ctx: ConfigurationContext):
        self._base_context = ctx

        self._load_or_create_configuration()

        self._user_accesses = UserAccessRegistry(self._base_context)

        self.server = grpc.server(
            # Ensures PiRogue administration tasks are done one at a time
            futures.ThreadPoolExecutor(max_workers=1), maximum_concurrent_rpcs=1,
            # Intercepts each call to authenticate against authorization Token
            interceptors=(TokenValidationInterceptor(self.get_current_token,self._user_accesses),),
            # Avoids reusable port. We prefer to warn the daemon caller instead.
            options=(('grpc.so_reuseport', 0),)
        )

        system_servicer_impl = SystemServicerImpl(self._base_context)
        system_servicer_impl.register_to_server(self.server)

        network_servicer_impl = NetworkServicerImpl(
            self._base_context,
            get_port_func=self.get_current_port,
            get_token_func=self.get_current_token,
            reset_token_func=self.reset_token,
        )
        network_servicer_impl.register_to_server(self.server)

        services_servicer_impl = ServicesServicerImpl(self._base_context)
        services_servicer_impl.register_to_server(self.server)

        access_server_impl = AccessServicerImpl(
            self._base_context,
            get_port_func=self.get_current_port,
            get_token_func=self.get_current_token,
            reset_token_func=self.reset_token,
            user_accesses=self._user_accesses,
        )
        access_server_impl.register_to_server(self.server)

        port = self.server.add_insecure_port(f"ip6-localhost:{self._port}")
        logger.info("Listening on ip6-localhost:%d", port)
        port = self.server.add_insecure_port(f"localhost:{self._port}")
        logger.info("Listening on localhost:%d", port)

    def get_current_port(self) -> int:
        return int(self._port)

    def get_current_token(self) -> str:
        return self._token

    def reset_token(self):
        self._generate_fresh_token()

    def serve_n_block(self):
        self.server.start()
        self.server.wait_for_termination()

    def _load_or_create_configuration(self):
        config_path = Path(self._base_context.var_dir, 'daemon.yaml')

        if not config_path.exists():
            logger.info("No current configuration: %s", config_path)
            self._generate_initial_configuration()

        loaded_config = yaml.safe_load(config_path.read_text())
        if isinstance(loaded_config, dict):  # Prevents existing but empty file
            self._port = loaded_config['port']
            self._token = loaded_config['token']

        assert isinstance(self._port, int)
        assert self._port not in (None, 0)
        assert isinstance(self._token, str)
        assert self._token not in (None, '')

    def _generate_initial_configuration(self):
        self._port = PIROGUE_ADMIN_TCP_PORT
        self._generate_fresh_token()

    def _generate_fresh_token(self):
        self._token = secrets.token_urlsafe(64)
        self._save_configuration()

    def _save_configuration(self):
        daemon_config_path = Path(self._base_context.var_dir, 'daemon.yaml')
        self._write_configuration_file(daemon_config_path, {
            'port': self._port,
            'token': self._token,
        })
        client_config_path = Path(self._base_context.var_dir, 'client.yaml')
        self._write_configuration_file(client_config_path, {
            'host': 'localhost',
            'port': self._port,
            'token': self._token,
        })

    def _write_configuration_file(self, config_path: Path, config: dict):
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w', encoding="utf-8") as out_fd:
            yaml.safe_dump(config, out_fd,
                           sort_keys=False,
                           default_flow_style=False,
                           encoding="utf-8",
                           allow_unicode=True)
        logger.info("New configuration written: %s", config_path)


def serve():

    global ADMIN_CONFIG_DIR, ADMIN_VAR_DIR, WORKING_ROOT_DIR
    ADMIN_CONFIG_DIR = os.getenv('PIROGUE_ADMIN_CONFIG_DIR', ADMIN_CONFIG_DIR)
    ADMIN_VAR_DIR = os.getenv('PIROGUE_ADMIN_VAR_DIR', ADMIN_VAR_DIR)
    WORKING_ROOT_DIR = os.getenv('PIROGUE_WORKING_ROOT_DIR', WORKING_ROOT_DIR)

    parser = argparse.ArgumentParser(
        epilog='''LOG_LEVEL must be one of
        DEBUG, INFO, WARNING (default), ERROR or CRITICAL
        ''')
    parser.add_argument('--commit', action='store_true',
                        help='''disable dry-run mode and commit changes (writing system files and
                        executing hooks)''')
    # FIXME: reseting token externaly should 'notify' current running daemon to restart
    parser.add_argument('--reset-token', '--reset', action='store_true',
                        help='''reset authentication token
                        and (re)generate configuration files''')
    parser.add_argument('--log-level', '--log', default='WARNING',
                        help='''set log level to LOG_LEVEL''')

    args = parser.parse_args()

    logging_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(logging_level, int):
        raise ValueError(f'Invalid log level: {args.log_level}')

    logging.basicConfig(encoding='utf-8', level=logging_level)

    base_ctx = ConfigurationContext(
        WORKING_ROOT_DIR, ADMIN_CONFIG_DIR, ADMIN_VAR_DIR,
        args.commit, False)
    pirogue_admin_daemon = PiRogueAdminDaemon(base_ctx)

    if args.reset_token:
        pirogue_admin_daemon.reset_token()
        logger.info('Admin token reset done')
        return

    # Start serving now
    pystemd.daemon.notify(False, ready=1,
                          status="pirogue-admin-daemon running")
    pirogue_admin_daemon.serve_n_block()
    pystemd.daemon.notify(False, stopping=1,
                          status="pirogue-admin-daemon stopping")


if __name__ == "__main__":
    serve()
