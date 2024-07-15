"""
This module deals with package-provided configuration files.

Each package wanting to get configured via pirogue-admin can ship a directory
(preferably matching its name for consistency) under /usr/share/pirogue-admin/
with a top-level index.yaml file that lists variables and files.
"""

import copy
import hashlib
import os
import shlex
import subprocess
from pathlib import Path

import yaml

from .formatters import SUPPORTED_FORMATTERS


def get_size_and_digest(path: Path):
    """
    Helper function to compare file before/after, using size and one digest algorithm.
    """
    if not path.exists():
        return -1, None
    return path.stat().st_size, hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()


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
    def __init__(self, directory: Path):
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

        # TEMPORARY: pretend the current directory is the root of the filesystem.
        root = os.getcwd()

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
            print(f'should be running {shlex.split(action)}')
            performed_actions.append(action)
            #subprocess.check_call(shlex.split(action))

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


class PackageConfigLoader():
    """
    Generate PackageConfig instances based on an entry point directory.

    Additionally, check there are no clashes across variables they provide
    default values for.
    """
    def __init__(self, admin_dir: str):
        self.admin_dir = admin_dir

        self.configs: list[PackageConfig] = []
        for item in [path for path in Path(self.admin_dir).glob('*') if path.is_dir()]:
            self.configs.append(PackageConfig(item))

        self.variables: dict[str, str] = {}
        for config in self.configs:
            for variable, value in config.variables.items():
                if variable in self.variables:
                    raise ValueError(f'default variable {variable} redefined in {config.package}')
                self.variables[variable] = value

    def get_needed_variables(self):
        """
        Return all required variables for all AdminConfig instances.
        """
        variables = []
        for config in self.configs:
            for f in config.files:
                for variable in f['variables']:
                    variables.append(variable['name'])
        return sorted(set(variables))

    def apply_configuration(self, dynamic_variables: dict[str, str]):
        """
        Iterate over all files from all AdminConfig instances to apply the
        configuration.
        """
        # Start from default variables, and overlay dynamic variables:
        variables = copy.deepcopy(self.variables)
        for key, value in dynamic_variables.items():
            variables[key] = value

        # Make sure there are no missing variables:
        missing = [x for x in self.get_needed_variables() if x not in variables]
        if missing:
            raise ValueError(f'missing variables: {missing}')

        # Iterate over AdminConfig instances sorting them alphabetically, but we
        # could introduce some priority/order if needed:
        for config in sorted(self.configs, key=lambda x: x.package):
            config.apply_configuration(variables)
