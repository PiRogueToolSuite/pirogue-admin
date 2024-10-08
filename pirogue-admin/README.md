PiRogue Admin
=============

Introduction
------------

This component coordinates configuration updates across various PiRogue
components, like the following ones:

 - `pirogue-dashboard`, which configures the Grafana-powered dashboard;
 - `pirogue-eve-collector`, which configures the Suricata-powered event
   collection;
 - `pirogue-flow-inspector`, which configures the NFStream-powered DPI;
 - `pirogue-networking`, which configures various network-oriented components
   (`dnsmasq`, `hostapd`, `iptables`, and `nftables`).

Integration happens via a subdirectory below `/usr/share/pirogue-admin` (ideally
named like the package, for consistency), featuring a top-level `index.yaml` and
various templates that can be used to create/update configuration files using
some variables, also running actions when that happens.

This means that all those packages don't require a `postinst` script in the
general case, they can just leave it up to `pirogue-admin` to deal with
system-wide configuration.


Rationale
---------

While PiRogue initially targeted the Raspberry Pi, we'd like to make it possible
to support 3 modes of operations.

 - `access-point`: This is the original mode, traffic is collected on a wireless
   interface and routed through a wired interface (`wlan0` and `eth0`
   respectively on Raspberry Pi).
 - `appliance`: This is a generalization of the previous mode, making it
   possible to collect and route traffic from a wired interface to another one.
   It can be implemented on a mini-PC, workstation, or server with two Ethernet
   interfaces. It can also be used in a virtual machine.
 - `vpn`: This is an entirely new mode of operation, where only one existing
   interface is required, and where WireGuard can be set up to collect traffic
   via a VPN connection, routing it through the existing interface.

In all three cases, we distinguish between:

 - The *isolated network*, from which traffic is collected. It's either
   wireless-based (`access-point`), wired-based (`appliance`), or
   WireGuard-based (`vpn`).
 - The *external network*, to which the traffic is routed. This is also where
   incoming connections (to the dashboard's web interface and/or via SSH for
   administration purposes) are accepted. It would usually be wired-based.


Components
----------

**Please keep in mind this is a work in progress, and nothing is set in stone!**

 - `pirogue_admin.cmd.cli` is shipped as a `pirogue-admin` command,
   demonstrating current capabilities.
 - `pirogue_admin.package_config` deals with the aforementioned “package config”
   subdirectories, loading and validating their `index.yaml`, and providing ways
   to apply a configuration based on a set of variables.
 - `pirogue_admin.system_config` deals with detecting which network interfaces
   are available, which network tools are installed and in use, what the network
   configuration looks like and whether it was set up by PiRogue tools. It also
   implements heuristics to suggest the most appropriate settings to users.


Development environment
-----------------------

By default, `pirogue-admin` is in dry-run mode.

By default, `pirogue-admin` interprets absolute filepath from root filesystem `/`.


### Dry-run mode

Dry-run mode:
 - writes all destination files into `${CWD}/dry-run`
 - skips all sub command executions

By default, all `pirogue-admin` executions are in dry-run mode. To deactivate
this mode, you must use the explicit `--commit` parameter. 


### Working root directory

By default, `pirogue-admin` interprets absolute filepath from root filesystem `/`.

For development purpose, this can be overridden using the `PIROGUE_WORKING_ROOT_DIR`
environment variable.

E.g:
```bash
PIROGUE_WORKING_ROOT_DIR=./devel/my-dev-chroot pirogue-admin --help
```

This allows the developer to simulate pirogue administration, putting all `index.yaml` in
a fake root directory structure with all their related file needed at configuration
generation stage. For more information about pirogue configurable packages,
see [deb-packages project](https://github.com/PiRogueToolSuite/deb-packages/tree/virogue)

> [!NOTE] 
> When `--commit` is used in conjunction with a custom `PIROGUE_WORKING_ROOT_DIR`, changes are written
> to the `PIROGUE_WORKING_ROOT_DIR`.


### Examples
Dry running differential configuration changes, from stdin:
```bash
cat my-tiny-changes.yml | pirogue-admin --apply
```

Dry running differential configuration changes, from file:
```bash
pirogue-admin --apply my-tiny-changes.yml
```

Applying differential configuration changes:
```bash
cat my-tiny-changes.yml | pirogue-admin --apply --commit
```

Dry running full configuration changes and prevent from loading existing
configuration:
```bash
cat all-new-variables-set.yml | pirogue-admin --apply --from-scratch
```
