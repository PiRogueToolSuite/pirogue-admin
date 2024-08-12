# PiRogue Admin

## Fresh PiRogue installation

Prepare a VM or a Raspberry Pi with a debian-12 distro.

SSH to it and grant root access.

Install of the base system.
```shell
apt update
apt install pirogue-base
```

Get your PiRogue current configuration.
```shell
pirogue-admin-client system get-configuration
```

If you are on the same subnet as your PiRogue, you can browse to:
  * http://pirogue.local : for the landing page
  * http://pirogue.local/dashboard : for the dashboard login page

### Securing Dashboard access
Change the dashboard password.
```shell
pirogue-admin-client dashboard set-configuration --password 'MyNewPassword!'
```

### Configure remote access for LAN access

Goal:
  * Administrate the PiRogue remotely from another device

Condition:
  * Your administration computer is on the same subnet as the PiRogue. 
    Example: your PiRogue external ip address is `192.168.0.10`,
    your computer is `192.168.0.12`

Get the self-signed certificate
```shell
# on the PiRogue
pirogue-admin-client external-network get-administration-certificate
```

Copy the result and save it on your computer in a txt file called `pirogue-cert.pem`.

```shell
# on the PiRogue
pirogue-admin-client external-network get-administration-clis
```

The result are command lines to execute on your computer.

When done, you can administrate remotely the PiRogue.

### Configure remote access for PUBLIC access

Condition:
 * You have a Fully Qualified Domain Name routed to the external interface of the pirogue
 * You have authority on this FQDN (e.g: my-domain.net)
 * You have a public email address

```shell
# on the PiRogue
pirogue-admin-client external-network enable-public-exposure --domain my-pirogue.my-domain.net --email contact@my-domain.net
```
