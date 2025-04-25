
import socket
import os
from ipaddress import IPv4Address, IPv6Address, ip_address

from pyroute2.netlink.rtnl.ifaddrmsg import ifaddrmsg
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg

from pirogue_admin.package_config import ConfigurationContext, PackageConfigLoader
from pirogue_admin.cmd.cli import WORKING_ROOT_DIR, ADMIN_CONFIG_DIR, ADMIN_VAR_DIR
from pyroute2 import IPRoute
import logging

logging.basicConfig()
LOGLEVEL = os.environ.get('NET_CONFIG_MONITOR_LOGLEVEL', 'INFO').upper()
logging.basicConfig(level=LOGLEVEL)
logging.getLogger().setLevel(LOGLEVEL)


class IfaceWrapper:
    def __init__(self, event: ifinfmsg):
        self._event = event
        self._ipr = IPRoute()

    def __getattr__(self, item):
        """
        Retrieves the attribute value from the event object.

        Args:
            item (str): The name of the attribute to retrieve.

        Returns:
            Any: The value of the requested attribute, or None if it does not exist.
        """
        return self._event.get(item, None)

    def get_attr(self, name):
        """
        Retrieves a specific attribute from the event object by name.

        Args:
            name (str): The name of the attribute.

        Returns:
            Any: The value of the specified attribute.
        """
        return self._event.get_attr(name)

    def is_loopback(self) -> bool:
        """
        Checks if the network interface is a loopback interface.

        Returns:
            bool: True if the interface is a loopback interface, False otherwise.
        """
        return self.ifi_type == 772

    def is_ethernet(self) -> bool:
        """
        Checks if the network interface is an Ethernet interface.

        Returns:
            bool: True if the interface is an Ethernet interface, False otherwise.
        """
        return self.ifi_type == 1

    def has(self, ip: IPv4Address) -> bool:
        """
        Checks if the given IPv4 address is assigned to this interface.

        Args:
            ip (IPv4Address): The IPv4 address to check.

        Returns:
            bool: True if the address is assigned to the interface, False otherwise.
        """
        return ip in self.ipv4

    @property
    def ipv4(self) -> list[IPv4Address]:
        ip_list = []
        events: list[ifaddrmsg] = list(self._ipr.get_addr(family=2, index=self.index))
        for event in events:
            ip_list.append(
                IPv4Address(event.get_attr('IFA_ADDRESS'))
            )
        return ip_list

    @property
    def ipv6(self) -> list[IPv6Address]:
        ip_list = []
        events: list[ifaddrmsg] = list(self._ipr.get_addr(family=10, index=self.index))
        for event in events:
            ip_list.append(
                IPv6Address(event.get_attr('IFA_ADDRESS'))
            )
        return ip_list

    @property
    def name(self):
        return self._event.get_attr('IFLA_IFNAME')

    @property
    def mac_address(self):
        return self._event.get_attr('IFLA_ADDRESS')


EXTERNAL_INTERFACE_KEY = 'EXTERNAL_INTERFACE'
EXTERNAL_ADDRESS_KEY = 'EXTERNAL_ADDRESS'
ISOLATED_INTERFACE_KEY = 'ISOLATED_INTERFACE'
ISOLATED_ADDRESS_KEY = 'ISOLATED_ADDRESS'


class NetworkConfigurationMonitor:
    """
    A class to monitor and manage network configuration changes in real-time.

    This class listens for network events related to IP addresses and interfaces,
    processes the events, and performs actions such as reconfiguring addresses
    and updating system state. It provides utilities to identify changes in the
    network and execute dynamic reconfigurations when necessary.

    Major responsibilities:
    - Monitor network interfaces and their configurations.
    - Handle IP address assignment events for external and isolated interfaces.
    - Trigger reconfiguration of system state when required.
    """

    def __init__(self):
        """
        Initializes the NetworkConfigurationMonitor instance.

        This method sets up the initial state, including loading the IPRoute utility
        for interacting with the kernel's network stack, as well as defaulting the
        running and loaded flags to False. It also pre-defines placeholders for system
        configuration and network interfaces.
        """
        self.ipr = IPRoute()
        self.running = False
        self.loaded = False
        self.system_configuration: dict = {}
        self.network_interfaces: list[IfaceWrapper] = []

    @property
    def external_interface(self):
        iface_name = self.system_configuration.get(EXTERNAL_INTERFACE_KEY)
        return self.get_iface_by_name(iface_name)

    @property
    def isolated_interface(self):
        iface_name = self.system_configuration.get(ISOLATED_INTERFACE_KEY)
        return self.get_iface_by_name(iface_name)

    def get_iface_by_name(self, name):
        """
        Retrieves a network interface by its name.

        Args:
            name (str): The name of the network interface to be retrieved.

        Returns:
            IfaceWrapper or None: The interface object if found, or None otherwise.
        """
        for iface in self.network_interfaces:
            if iface.name == name:
                return iface
        return None

    def get_iface_by_index(self, index):
        """
        Retrieves a network interface by its index.

        Args:
            index (int): The index of the network interface to be retrieved.

        Returns:
            IfaceWrapper or None: The interface object if found, or None otherwise.
        """
        for iface in self.network_interfaces:
            if iface.index == index:
                return iface
        return None

    def load_iface_list(self):
        """
        Loads and returns a list of all current network interfaces on the system.

        Returns:
            list[IfaceWrapper]: A list of wrapped network interface objects.
        """
        ifaces: list[IfaceWrapper] = []
        events: list[ifinfmsg] = list(self.ipr.get_links())
        for event in events:
            ifaces.append(IfaceWrapper(event))
        return ifaces

    @staticmethod
    def valid_address_purpose(ip: IPv4Address) -> bool:
        """
        Determines the validity of an IPv4 address for PiRogue.

        This method checks whether the given IPv4 address satisfies conditions
        making it suitable for use as a valid external address. The conditions
        of validity are:
        - The address must be private (non-public).
        - It must not be a loopback address (e.g., 127.0.0.1).
        - It must not be a link-local address (e.g., 169.254.x.x).
        - The address must not be unspecified (0.0.0.0).
        - It must not belong to the multicast range (224.0.0.0/4).
        - It must not be a reserved address (addresses reserved for special uses).

        Args:
            ip (IPv4Address): The IP address to be validated.

        Returns:
            bool: True if the IP address meets all conditions above, False otherwise.
        """

        return (ip.is_private
                and not ip.is_loopback
                and not ip.is_link_local
                and not ip.is_unspecified
                and not ip.is_multicast
                and not ip.is_reserved)

    @staticmethod
    def load_system_config() -> dict:
        """
        Loads the system configuration.

        Returns:
            dict: A dictionary containing the current configuration settings.
        """
        ctx = ConfigurationContext(WORKING_ROOT_DIR, ADMIN_CONFIG_DIR, ADMIN_VAR_DIR, False, False)
        config_loader = PackageConfigLoader(ctx)
        return config_loader.current_config

    def load_state(self):
        """
        Loads the system configuration and network interfaces.

        This method reads the system configuration and populates the list of
        network interfaces to reflect the current state of the system's network
        configuration.
        """
        self.loaded = True
        self.system_configuration: dict = self.load_system_config()
        self.network_interfaces: list[IfaceWrapper] = self.load_iface_list()

    def check_initial_state(self):
        if not self.loaded:
            return

        external_iface_name = self.system_configuration.get(EXTERNAL_INTERFACE_KEY)
        external_iface = self.get_iface_by_name(external_iface_name)
        if external_iface.ipv4:
            self.reconfigure_external_address(external_iface.ipv4[0])


    def reconfigure_external_address(self, new_ip_address: IPv4Address):
        """
        Reconfigures the external interface with a new external IPv4 address.

        This method checks whether the new IP address differs from the currently configured address. It verifies whether the
        event pertains to the configured external interface and checks
        the validity of the IP address. If the external interface has
        been assigned a new address requiring reconfiguration, it triggers
        the reconfiguration process.
        If they are different, it updates the system configuration to use the new address.
        In case of an error during reconfiguration, it restores the previous configuration.

        Args:
            new_ip_address (IPv4Address): The new IPv4 address to be assigned to the external interface.

        Exceptions:
            Logs and handles any exceptions raised during the configuration update process.

        Logic:
            - Compares the new IP address with the existing IP address.
            - If the addresses differ, updates the configuration using `ConfigurationContext` and `PackageConfigLoader`.
            - In the event of a failure, reverts to the original IP address and reloads the system state.
        """
        configured_external_iface, configured_external_addr = (
            self.system_configuration.get(EXTERNAL_INTERFACE_KEY),
            ip_address(self.system_configuration.get(EXTERNAL_ADDRESS_KEY)),
        )
        if configured_external_addr == new_ip_address:
            logging.debug(f'No reconfiguration needed {configured_external_addr} == {new_ip_address}')
            return
        if type(configured_external_addr) is IPv6Address:
            logging.debug(f'The configured IP address is an IP v6, ignore {configured_external_addr}')
            return
        logging.info(f'⚡️ Reconfiguring the external interface: {configured_external_addr} -> {new_ip_address}')
        ctx = ConfigurationContext(WORKING_ROOT_DIR, ADMIN_CONFIG_DIR, ADMIN_VAR_DIR, True, False)
        loader = PackageConfigLoader(ctx)
        new_configuration = {EXTERNAL_ADDRESS_KEY: str(new_ip_address)}
        try:
            loader.apply_configuration(new_configuration, False)
        except Exception as e:
            logging.error('Unable to reconfigure the PiRogue, contact your administrator.')
            logging.exception(e)
            self.debug(None)
            logging.error('Reverting to the previously configured IP address.')
            new_configuration = {EXTERNAL_ADDRESS_KEY: str(configured_external_addr)}
            loader.apply_configuration(new_configuration, False)
        finally:
            self.load_state()

    def _new_ip_address_assigned(self, event):
        """
        Handles events for new IP addresses assigned to a network interface.

        This method processes an event indicating that a new IP address
        has been added to a network interface.

        Args:
            event (dict): The network event data containing details of the
                interface, the new IP address assigned, and other metadata.
        """
        configured_external_iface, configured_external_addr = (
            self.system_configuration.get(EXTERNAL_INTERFACE_KEY),
            ip_address(self.system_configuration.get(EXTERNAL_ADDRESS_KEY)),
        )
        # if type(configured_external_addr) is IPv6Address:
        #     logging.debug(f'The configured IP address is an IP v6, ignore {configured_external_addr}')
        #     return
        event_iface = self.get_iface_by_index(event['index'])
        event_ifname = event_iface.name
        event_ipaddr = IPv4Address(event.get_attr('IFA_ADDRESS'))
        if event_ifname != configured_external_iface or not self.valid_address_purpose(event_ipaddr):
            logging.debug(f'Nothing interesting here {event}')
            return
        logging.info(f'Event received for the external iface {configured_external_iface}/{event_ipaddr}')
        logging.info(f'⚡️IP {event_ipaddr} added to interface {event_ifname}')
        logging.debug(f'Need reconfiguration? {not event_iface.has(configured_external_addr)}')
        if not event_iface.has(configured_external_addr):
            logging.info(f'A reconfiguration is needed, {event_ipaddr} != {configured_external_addr}')
            self.reconfigure_external_address(event_ipaddr)

    def dispatch(self, event):
        """
        Processes network events and takes appropriate actions based on the type and content of the event.

        - If a new IPv4 address (RTM_NEWADDR) is added to the external interface, this method triggers a system state
          reload, logs the event, and evaluates if a reconfiguration is necessary.
        - If an event related to neighbor changes (RTM_NEWNEIGH / RTM_DELNEIGH) occurs on the isolated interface, it
          logs the updated neighbor details.
        """
        if event['event'] == 'RTM_NEWADDR' and event['family'] == 2 and event['index'] == self.external_interface.index:
            self.load_state()
            self.debug(event)
            self._new_ip_address_assigned(event)
        elif event['event'] in ['RTM_NEWNEIGH', 'RTM_DELNEIGH'] and event['ifindex'] == self.isolated_interface.index:
            try:
                self.debug_neighbours()
            except:
                pass

    def run(self):
        """
        Monitors network configuration changes and handles events in real-time.

        This method is the main execution loop that continuously listens to network events
        using the IPRoute interface. It processes events related to changes in the IP addresses
        or neighbors and takes actions such as reconfiguring the system or logging state updates.

        Major Steps:
        1. Initializes monitoring and binds IPRoute for async caching.
        2. Enters an infinite loop for monitoring events until explicitly stopped.
        3. On receiving an event:
            - If it is the first event, loads the current system state.
            - Dispatches the event based on its type and handles relevant actions.

        Exceptions:
            Handles KeyboardInterrupt to ensure resources such as IPRoute
            are properly released before exiting.

        Logging:
            Logs system initialization, events received, and any reconfigurations performed during execution.
        """

        logging.info('Starting the monitor')
        first_event = True
        self.running = True
        self.ipr.bind(async_cache=True)
        while self.running:
            try:
                for event in self.ipr.get():
                    if first_event:
                        first_event = False
                        self.load_state()
                        if LOGLEVEL == 'DEBUG':
                            logging.debug('*** Initial system state')
                            self.debug(None)
                        self.check_initial_state()
                    if self.loaded:
                        self.dispatch(event)
            except KeyboardInterrupt:
                logging.info('Stopping the monitor...')
                self.ipr.close()
                return

    def debug_current_state(self):
        """
        Logs details about the current state of the external network interface.

        This includes information from system configuration and actual interface
        state retrieved from the `IfaceWrapper` for debugging purposes.
        """
        external_iface_name = self.system_configuration.get(EXTERNAL_INTERFACE_KEY)
        external_iface_ip = self.system_configuration.get(EXTERNAL_ADDRESS_KEY)
        external_iface = self.get_iface_by_name(external_iface_name)
        logging.info('-- External interface')
        logging.info(f'Configuration: {external_iface_name}/{external_iface_ip}')
        logging.info(f'System: {external_iface_name}/{external_iface.ipv4}')

    def debug_neighbours(self):
        """
        Logs details about the neighbors visible on the isolated interface.

        This includes IP, MAC address, and a hostname (if resolvable) for
        debugging and inspection of neighboring devices.
        """
        logging.info('-- Neighbours')
        for n in self.ipr.get_neighbours(ifindex=self.isolated_interface.index, family=2):
            n_ip = n.get_attr('NDA_DST')
            n_mac = n.get_attr('NDA_LLADDR')
            n_name = 'unknown'
            try:
                n_name = socket.gethostbyaddr(n_ip)[0]
            except:
                pass
            action = 'connected to' if n_mac else 'disconnected from'
            logging.info(f'[{n_name}]: {n_ip}/{n_mac} {action} {self.isolated_interface.name}')

    def debug(self, event):
        logging.info('Debug info:')
        logging.info('-- Network interfaces')
        for iface in self.network_interfaces:
            logging.info \
                (f'[{iface.index}]: {iface.name}/{iface.mac_address} - IP v4: {iface.ipv4} - IP v6: {iface.ipv6}')
        self.debug_current_state()
        self.debug_neighbours()
        if event:
            logging.info('-- Received event')
            logging.info(event)
        logging.info('-----------')

    def stop(self):
        """
        Stops the network configuration monitor.

        This method halts the infinite monitoring loop and closes the IPRoute
        interface to ensure all resources are released.
        """
        self.running = False
        self.ipr.close()
        logging.info("Monitor stopped.")


def main():
    daemon = NetworkConfigurationMonitor()
    try:
        daemon.run()
    except KeyboardInterrupt:
        daemon.stop()


if __name__ == "__main__":
    main()
