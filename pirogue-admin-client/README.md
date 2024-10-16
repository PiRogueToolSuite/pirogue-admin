# pirogue-admin-client

## Command line ecosystem

This CLI is organized as follows: `pirogue-admin-cli` `<section>` `<action>` `[parameters]`.

The `--help` command can be used on every piece of the CLI, e.g:
```bash
$ pirogue-admin-client --help
# main level help
$ pirogue-admin-client system --help
# system section level help
$ pirogue-admin-client system get-configuration --help
# get-configuration command help
```

## Available commands
### System section
```shell
pirogue-admin-client system get-configuration-tree
pirogue-admin-client system get-configuration
pirogue-admin-client system get-operating-mode
pirogue-admin-client system get-status
pirogue-admin-client system get-packages-info
pirogue-admin-client system get-hostname
pirogue-admin-client system set-hostname <hostname>
pirogue-admin-client system get-locale
pirogue-admin-client system set-locale <locale>
pirogue-admin-client system get-timezone
pirogue-admin-client system set-timezone <timezone>
```

```shell
pirogue-adminc-client system list-connected-devices
```

### External network section
```shell
pirogue-admin-client external-network reset-administration-token
pirogue-admin-client external-network get-administration-token
pirogue-admin-client external-network get-administration-certifcate
pirogue-admin-client external-network get-administration-clis
pirogue-admin-client external-network enable-public-access --domain <public_domain_name> --email <administration_email>
pirogue-admin-client external-network disable-public-access
```

### VPN section
```shell
pirogue-admin-client vpn list-peers
pirogue-admin-client vpn get-peer <id>
pirogue-admin-client vpn add-peer [--comment <comment>] [--public-key <pubkey>]
pirogue-admin-client vpn delete-peer <id>
```

### WiFi section
```shell
pirogue-admin-client wifi get-configuration
pirogue-admin-client wifi set-configuration [--ssid <ssid>] [--passphrase <password>] [--country-code <cc>]
```

### Isolated network section
```shell
pirogue-admin-client isolated-network open-port <incoming-port> [--outgoing-port <port>]
pirogue-admin-client isolated-network close-port [--incoming-port <port>] 
pirogue-admin-client isolated-network list-open-ports
```


### Suricata section
```shell
pirogue-admin-client suricate-rules add-source <name> <url>
pirogue-admin-client suricate-rules del-source <name>
pirogue-admin-client suricate-rules list-sources
```

### Dashboard section
```shell
pirogue-admin-client dashboard get-configuration
pirogue-admin-client dashboard set-configuration --password <password>
```

## Writing your own tool
`pirogue-admin-client` is available as python library.
Here are examples to illustrate its usage.

### On a pirogue system
If the tool you're writing will run directly on a PiRogue system,
you to not need authentication information, 
`PirogueAdminClientAdapter` will found them for you:
```python
from pirogue_admin_client import PirogueAdminClientAdapter

paca = PirogueAdminClientAdapter()

# Now, use it as you want
current_config_map = paca.get_configuration()

# etc ...
```

### Remote usage
If you plan to run your tool directly, you will need administration
authentication information:
```python
from pirogue_admin_client import PirogueAdminClientAdapter

pirogue_host = 'my-pirogue-instance.pts-project.org'
pirogue_port = 50051
pirogue_admin_token = "a-long-token-to-retrieve-on-pirogue"

paca = PirogueAdminClientAdapter(
    host=pirogue_host,
    port=pirogue_port,
    token=pirogue_admin_token,)

# Then, use it as usual
current_config_map = paca.get_configuration()

# etc ...
```
