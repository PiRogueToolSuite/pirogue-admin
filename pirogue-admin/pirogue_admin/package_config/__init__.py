"""
This module deals with package-provided configuration files.

Each package wanting to get configured via pirogue-admin can ship a directory
(preferably matching its name for consistency) under /usr/share/pirogue-admin/
with a top-level index.yaml file that lists variables, files, and actions.
"""

import copy
import hashlib
import os
import shlex
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import TextIO

import yaml

from pirogue_admin.system_config import SystemConfig
from .formatters import SUPPORTED_FORMATTERS


def get_size_and_digest(path: Path):
    """
    Helper function to compare file before/after, using size and one digest algorithm.
    """
    if not path.exists():
        return -1, None
    return path.stat().st_size, hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()


@dataclass
class ConfigurationContext:
    """
    Holds PiRogue admin execution context through all internal tools.
    By default, an execution context is in dry-run mode, meaning,
    no system file will be altered, no hook will be executed.
    """
    pirogue_working_root_dir: str
    pirogue_admin_dir: str
    pirogue_var_dir: str
    commit: bool = False
    from_scratch: bool = False

    @staticmethod
    def path_concat(*paths):
        """
        Concatenates and simplifies paths, even there are multiple apparent absolute paths.
        pathlib.join and pathlib.Path does not support fluent path concatenation.
        WARNING: this implementation does not support Windows systems.
        e.g:
          - path_concat(['/other/path', '/usr/bin']) will result to '/other/path/usr/bin'
          - path_concat(['/other/path', '../usr/bin']) will result to '/other/usr/bin'

        :param paths: paths to concat
        :return: a string representation of the concatenation
        """
        return os.path.normpath(os.sep.join(paths))

    @property
    def dry_run(self) -> bool:
        """
        Returns True if this configuration context is running in dry-run mode.
        """
        return not self.commit

    @property
    def root_dir(self) -> str:
        """
        Returns the 'root' directory depending on the current dry-run mode.
        """
        if self.dry_run:
            return ConfigurationContext.path_concat(os.getcwd(), 'dry-run')
        return self.pirogue_working_root_dir

    @property
    def admin_dir(self) -> str:
        """
        Returns the PiRogue share/admin directory depending on the current
        PIROGUE_WORKING_ROOT_DIR configuration.
        """
        return ConfigurationContext.path_concat(self.pirogue_working_root_dir,
                                                self.pirogue_admin_dir)

    @property
    def var_dir(self) -> str:
        """
        Returns the PiRogue var/admin directory depending on the current
        PIROGUE_WORKING_ROOT_DIR configuration.
        """
        return ConfigurationContext.path_concat(self.pirogue_working_root_dir,
                                                self.pirogue_var_dir)

    @property
    def write_var_dir(self) -> str:
        """
        Returns the PiRogue var/admin directory depending on the current dry-run mode.
        """
        if self.dry_run:
            return ConfigurationContext.path_concat(self.root_dir, self.pirogue_var_dir)
        return self.var_dir

    def __repr__(self):
        return f"ConfigurationContext(" \
               f"pirogue_working_root_dir={self.root_dir}, " \
               f"pirogue_admin_dir={self.admin_dir}, " \
               f"pirogue_var_dir={self.var_dir}, " \
               f"dry_run={self.dry_run} from_scratch={self.from_scratch})"


class PackageConfig:
    """
    Things we might have in there:

     - variables, list of variable name/default values.

     - files, list of src/dst + actions and possibly conditions (we need to
       think what to do when a condition isn't met, and how to express it, see
       actions_otherwise)

     - actions, to avoid repeating ourselves (e.g. to enable/restart grafana
       from each and every configuration file it requires). Such actions require
       name: "action-name" while all other actions are expected to be shell
       command lines.
    """
    def __init__(self, ctx: ConfigurationContext, directory: Path):
        self.ctx = ctx
        self.directory = directory
        self.package = directory.name
        self.variables: dict[str, str] = {}
        self.files: list[dict] = []
        self.parse_index(directory / 'index.yaml')

    def apply_configuration(self, variables: dict[str, str]):
        """
        Create or update files and run associated actions whenever a change
        happens.
        """
        print(f'applying configuration for {self.package}')

        root = self.ctx.root_dir

        # FIXME: The intent behind factorized "actions" in the dashboard case
        # wasn't bad, but the implementation won't work as we're going to run
        # action1 and action2 n times, since those are intertwined. Reordering
        # action to be able to uniquify the list wouldn't be reasonable (it
        # could break other usecases)…
        #
        # Maybe use action1 && action2 syntax, if that's something we can live
        # with (via subprocess and/or shlex).
        #
        # Actually, the question is whether we want actions to be scheduled for
        # all files, then run them altogether at the end, we could deduplicate
        # during the loop, spotting which ones were run already. If we want to
        # run actions associated with a file right after deploying it, we can't
        # deduplicate.
        #
        # It might be more robust to have all files put into place first, then
        # run all actions in the end: maybe some services could require several
        # files to be deployed before being able to (re)start.
        pending_actions = []
        for f in self.files:
            template = (self.directory / f['src']).read_text()
            for variable in f['variables']:
                # Initially we were passing only the value for the specific
                # variable name we were interested in, but at least computing
                # the DHCP range for dnsmasq requires looking at an extra
                # variable.
                #
                # Therefore, pass all variables as a second argument all the
                # time, even if only that particular one function requires
                # looking into the value of a particular one variable, keeping
                # genericity:
                value = SUPPORTED_FORMATTERS[ variable['type'] ](variables[variable['name']],
                                                                 variables)
                template = template.replace(variable['token'], value)

            dst = Path(root + f['dst'])
            size1, digest1 = get_size_and_digest(dst)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(template)
            size2, digest2 = get_size_and_digest(dst)
            if size1 == size2 and digest1 == digest2:
                continue
            print(f'{f["dst"]} changed, scheduling associated actions')
            pending_actions.extend(f['actions'])

        performed_actions = []
        for action in pending_actions:
            if action in performed_actions:
                print(f'skipping {action}, already done')
                continue
            print(f'running {shlex.split(action)}')
            performed_actions.append(action)
            if self.ctx.dry_run:
                print(f'dry-running {shlex.split(action)} ...')
            else:
                subprocess.check_call(shlex.split(action))
            print(f'running {shlex.split(action)}: done.')

    def get_needed_variables(self) -> list[str]:
        """
        Return all required variables for this PackageConfig instance.
        """
        variables = set()
        for f in self.files:
            for variable in f['variables']:
                variables.add(variable['name'])
        return sorted(variables)

    def parse_index(self, index: Path):
        """
        Parse the top level: check keys, then traverse.
        """
        meta = yaml.safe_load(index.read_text())
        # Make sure there are no unexpected keys at the top-level:
        for key in meta:
            if key not in ['variables', 'files', 'actions']:
                raise ValueError(f'unexpected {key} at the top-level')

        # The actions section is only here to avoid repeating ourselves in the
        # files section, is useful during parsing, but doesn't require storing:
        self.parse_index_variables(meta.get('variables', []))
        self.parse_index_files(meta.get('files', []), meta.get('actions', {}))

    def parse_index_variables(self, variables: list):
        """
        Parse variables section: name/default pairs.
        """
        for variable in variables:
            # Each variable must be exactly a name/default pair:
            if sorted(variable.keys()) != ['default', 'name']:
                raise ValueError(f'unexpected keys in {variable}')

            # Both must be a string:
            if not isinstance(variable['name'], str):
                raise ValueError(f'variable name must be a string in {variable}')
            if not isinstance(variable['default'], str):
                raise ValueError(f'variable default must be a string in {variable}')

            # It must not clash with the SystemConfig namespace:
            if variable['name'].startswith(SystemConfig.PREFIX):
                raise ValueError(f'name cannot start with {SystemConfig.PREFIX}: {variable}')

            # Store if everything looks good:
            self.variables[ variable['name'] ] = variable['default']

    def parse_index_files(self, files: list, actions: dict):
        """
        Parse files: list of files with possibly many details.

        This includes but is not limited to: src, dst, variables, actions.
        """
        if actions:
            for key, value in actions.items():
                if not isinstance(key, str):
                    raise ValueError(f'action key {key} must be a string')
                if not value or not all(isinstance(s, str) for s in value):
                    raise ValueError(f'action value for key {key} must be a list of strings')

        for orig_f in files:
            f = copy.copy(orig_f)

            # FIXME: check for unsupported keys

            # Source and destination:
            if 'src' not in f or not isinstance(f['src'], str):
                raise ValueError(f'file must have an src, and it must be a string in {f}')
            if 'dst' not in f or not isinstance(f['dst'], str):
                raise ValueError(f'file must have a dst, and it must be a string in {f}')
            # dst can be a full filename or a parent directory, adjust if needed:
            if f['dst'].endswith('/'):
                f['dst'] += f['src']

            if not (self.directory / f['src']).exists():
                raise ValueError(f'file src missing in directory {f}')

            # Variables all have a name, a type that defaults to string (we
            # might want to compute something like a DHCP range for dnsmasq,
            # a matching operator for Grafana, etc.), and a token that defaults
            # to @<variable>@ to make sure we can adjust any kind of
            # configuration file:
            if 'variables' in f and not isinstance(f['variables'], list):
                raise ValueError(f'file must have a variables, and it must be a list in {f}')
            final_variables = []
            for variable in f.get('variables', []):
                v = copy.copy(variable)  # pylint: disable=invalid-name
                # FIXME: Make sure there are no unexpected keys.
                if 'name' not in variable or not isinstance(variable['name'], str):
                    raise ValueError(f'variable must have a name, and it must be a string in {v}')

                # Optional field; should validate it's a string if present.
                if 'type' not in variable:
                    v['type'] = 'string'
                if v['type'] not in SUPPORTED_FORMATTERS:
                    raise ValueError(f'unsupported variable type in {v}')

                # Optional field; should validate it's a string if present.
                if 'token' not in variable:
                    v['token'] = f'@{variable["name"]}@'

                final_variables.append(v)
            f['variables'] = final_variables

            # Actions can be a list of strings (shell commands) and/or "name":
            # "action-name" pointers using the actions indirection:
            final_actions = []
            if 'actions' not in f or not isinstance(f['actions'], list):
                raise ValueError(f'file must have an actions, and it must be a list in {f}')
            for action in f['actions']:
                # Easy case:
                if isinstance(action, str):
                    final_actions.append(action)
                    continue
                if not isinstance(action, dict):
                    raise ValueError(f'action must be a string or a dict in {action}')
                if list(action.keys()) != ['name']:
                    raise ValueError(f'action dict must have exactly one "name" key in {action}')
                if not isinstance(action['name'], str):
                    raise ValueError(f'action["name"] must be a string in {action}')
                if action['name'] not in actions:
                    raise ValueError(f'action["name"] must be a valid reference in {action}')
                final_actions.extend(actions[action['name']])
            f['actions'] = final_actions

            self.files.append(f)

    def __repr__(self):
        return f'package={self.package}\nvariables={self.variables}\nfiles={self.files}\n'


class PackageConfigLoader:
    """
    Generate PackageConfig instances based on an entry point directory.

    Additionally, check there are no clashes across variables they provide
    default values for.
    """
    def __init__(self, ctx: ConfigurationContext):
        self.ctx = ctx

        # We have a single SystemConfig for pirogue-admin itself, and many
        # PackageConfig instances (~ /usr/share/pirogue-admin/* directories):
        self.system_config = SystemConfig()
        self.configs: list[PackageConfig] = []
        for item in [path for path in Path(self.ctx.admin_dir).glob('*')
                     if path.is_dir() or path.is_symlink()]:
            self.configs.append(PackageConfig(self.ctx, item))

        self.variables: dict[str, str] = {}
        for config in self.configs:
            for variable, value in config.variables.items():
                if variable in self.variables:
                    raise ValueError(f'default variable {variable} redefined in {config.package}')
                self.variables[variable] = value

        # Load current config based on CLI flags and on config file's presence:
        self.current_config: dict[str, str] = {}
        if self.ctx.from_scratch:
            print('Loading current config (from scratch): empty')
            return

        current_config_path = Path(self.ctx.var_dir, 'config.yaml')
        if not current_config_path.exists():
            print(f"No current configuration: {current_config_path}")
            return

        loaded_current_config = yaml.safe_load(current_config_path.read_text())
        if isinstance(loaded_current_config, dict):  # Prevents existing but empty file
            for key, value in loaded_current_config.items():
                self.current_config[key] = value

        print('Loading current config:', self.current_config)

    def get_configuration_tree(self):
        """
        Generates a configuration yaml tree map of the current pirogue admin ecosystem.

        :return a dictionary structure of the configuration
        """
        # Accept (very) short names in this function => pylint: disable=invalid-name
        by_package = {}
        by_file = {}
        by_variable = {}
        by_action = {}

        for s in self.configs:
            by_package[s.package] = {
                'files': set(),
                'variables': set(),
                'actions': set(),
            }
            for f in s.files:
                by_file[f['dst']] = by_file.get(f['dst']) or {
                    'packages': set(),
                    'variables': set(),
                    'actions': set(),
                }
                by_file[f['dst']]['packages'].add(s.package)
                by_package[s.package]['files'].add(f['dst'])

                for v in f['variables']:
                    by_variable[v['name']] = by_variable.get(v['name']) or {
                        'packages': set(),
                        'files': set(),
                        'actions': set(),
                    }
                    if v['name'] in self.variables:
                        by_variable[v['name']]['default'] = self.variables[v['name']]
                    by_variable[v['name']]['packages'].add(s.package)
                    by_variable[v['name']]['files'].add(f['dst'])

                    by_package[s.package]['variables'].add(v['name'])
                    by_file[f['dst']]['variables'].add(v['name'])

                for a in f['actions']:
                    by_action[a] = by_action.get(a, {
                        'packages': set(),
                        'files': set(),
                        'variables': set(),
                    })
                    by_action[a]['packages'].add(s.package)
                    by_action[a]['files'].add(f['dst'])

                    by_package[s.package]['actions'].add(a)
                    by_file[f['dst']]['actions'].add(a)

                    for v in f['variables']:
                        by_action[a]['variables'].add(v['name'])
                        by_variable[v['name']]['actions'].add(a)

        whole_map = {
            'packages': by_package,
            'files': by_file,
            'variables': by_variable,
            'actions': by_action,
        }

        # FIXME: Find a way to avoid set() conversion to list()
        # yaml dumps set()s differently than list()s:
        # yaml appends '!!set' keyword to all set() dumps
        # it should be possible to tweak yaml.dump invocation with some arguments to avoid this
        # behavior.
        for s in whole_map:
            for k in whole_map[s]:
                for fk in whole_map[s][k]:
                    if isinstance(whole_map[s][k][fk], set):
                        whole_map[s][k][fk] = sorted(whole_map[s][k][fk])

        return whole_map

    def dump_current_configuration(self, output: TextIO, notice_preamble: bool = False):
        """
        Writes the current configuration set to the given output stream. Can
        write user notice as header in the dump.

        :param output: a valid text output stream
        :param notice_preamble: appends a 'dot not edit' user header notice if True

        """
        if notice_preamble:
            output.write('# This file is generated\n')
            output.write('# Do not edit this file directly\n')
            output.write('# Use pirogue-admin tools to modify this PiRogue configuration\n')
        yaml.safe_dump(self.current_config, output,
                       sort_keys=False,
                       default_flow_style=False,
                       encoding="utf-8",
                       allow_unicode=True)

    def get_needed_variables(self) -> list[str]:
        """
        Return all required variables for SystemConfig and for all PackageConfig
        instances.
        """
        variables = self.system_config.get_needed_variables()
        for config in self.configs:
            variables.extend(config.get_needed_variables())
        return sorted(set(variables))

    def apply_configuration(self, dynamic_variables: dict[str, str]):
        """
        Iterate over all files from all PackageConfig instances to apply the
        configuration.
        """
        # Start from default variables, and overlay dynamic variables:
        variables = copy.deepcopy(self.variables)

        # Preloads each current_config
        for key, value in self.current_config.items():
            variables[key] = value

        # Applies new variables set
        for key, value in dynamic_variables.items():
            variables[key] = value

        # Make sure there are no missing variables:
        missing = [x for x in self.get_needed_variables() if x not in variables]
        if missing:
            raise ValueError(f'missing variables: {missing}')

        if self.ctx.dry_run:
            print(f'notice: in dry-run mode, all files will be written locally to: '
                  f'{self.ctx.root_dir}')

        # Start by adjusting the system configuration (at least initially that's
        # about the network configuration for the isolated network):
        self.system_config.apply_configuration(variables)

        # Iterate over PackageConfig instances sorting them alphabetically, but we
        # could introduce some priority/order if needed:
        for config in sorted(self.configs, key=lambda x: x.package):
            config.apply_configuration(variables)

        # Assuming previous 'apply_configuration' did not raise any exception
        # Merge applied configuration to current configuration
        self.current_config = copy.deepcopy(variables)

        # Saves the current configuration
        destination_config_path = Path(self.ctx.write_var_dir, 'config.yaml')
        print(f'Writing configuration file to: {destination_config_path}')
        destination_config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(destination_config_path, 'w', encoding="utf-8") as out_fd:
            self.dump_current_configuration(out_fd, notice_preamble=True)