"""Netbox gathering functions tailored to the WMF needs."""

import logging

from re import subn

from collections import defaultdict
from typing import Any, DefaultDict, Dict, Optional

from ipaddress import ip_interface

from homer.netbox import BaseNetboxDeviceData

logger = logging.getLogger(__name__)

HOSTNAMES_TO_GROUPS: Dict[str, Dict] = {'aux-k8s-ctrl': {'group': 'k8s_aux'},
                                        'aux-k8s-worker': {'group': 'k8s_aux'},
                                        'centrallog': {'group': 'anycast', 'ipv4_only': True},
                                        'dns': {'group': 'anycast', 'ipv4_only': True},
                                        'doh': {'group': 'anycast'},
                                        'dse-k8s-worker': {'group': 'k8s_dse'},
                                        'dse-k8s-ctrl': {'group': 'k8s_dse'},
                                        'durum': {'group': 'anycast'},
                                        'ganeti': {'group': 'ganeti'},
                                        'kubemaster': {'group': 'k8s'},
                                        'kubernetes': {'group': 'k8s'},
                                        'kubestage': {'group': 'k8s_stage'},
                                        'kubestagemaster': {'group': 'k8s_stage'},
                                        'lvs': {'group': 'pybal', 'ipv4_only': True},
                                        'ml-serve': {'group': 'k8s_mlserve'},
                                        'ml-serve-ctrl': {'group': 'k8s_mlserve'},
                                        'ml-staging-ctrl': {'group': 'k8s_mlstaging'},
                                        'ml-staging': {'group': 'k8s_mlstaging'},
                                        'mw': {'group': 'k8s'},
                                        'parse': {'group': 'k8s'},
                                        'wikikube-ctrl': {'group': 'k8s'},
                                        'wikikube-worker': {'group': 'k8s'}
                                        }

SWITCHES_ROLES = ('asw', 'cloudsw')
L3_SWITCHES_MODELS = ('qfx5120-48y-afi', 'qfx5120-48y-afi2')


class NetboxDeviceDataPlugin(BaseNetboxDeviceData):
    """WMF specific class to gather device-specific data dynamically from Netbox."""

    def __init__(self, netbox_api, device):
        """Initialize the instance."""
        super().__init__(netbox_api, device)
        self._device_interfaces = None
        self._device_ip_addresses = None
        self._interface_ip_addresses = None
        self._bgp_servers = []
        self.device_id = self._device.metadata['netbox_object'].id
        self.role = self._device.metadata['netbox_object'].role
        self.device_type = self._device.metadata['netbox_object'].device_type
        self.device_rack = self._device.metadata['netbox_object'].rack
        self.device_site = self._device.metadata['netbox_object'].site
        self.virtual_chassis = self._device.metadata['netbox_object'].virtual_chassis

    def fetch_device_interfaces(self):
        """Fetch interfaces from Netbox."""
        if not self._device_interfaces:
            if self.virtual_chassis:
                interfaces_filter = {'virtual_chassis_id': self.virtual_chassis.id}
            else:
                interfaces_filter = {'device_id': self.device_id}
            # Consume the generator or it will be empty if looped more than once.
            self._device_interfaces = list(self._api.dcim.interfaces.filter(**interfaces_filter))
        return self._device_interfaces

    def fetch_device_ip_addresses(self):
        """Fetch IPs from Netbox."""
        if not self._device_ip_addresses:
            # Consume the generator or it will be empty if looped more than once.
            self._device_ip_addresses = list(self._api.ipam.ip_addresses.filter(device_id=self.device_id))
        return self._device_ip_addresses

    def fetch_bgp_servers_l2(self, site: str = '') -> list:
        """Fetch VMs or VC servers with the BGP custom field from Netbox which peer with CRs."""
        if self._bgp_servers:
            return self._bgp_servers

        filters = {'status': 'active',
                   'role': 'server',
                   'cf_bgp': True}
        if site:  # slug
            filters['site'] = site

        # In the future we can filter here based on clusters (eg. L3 ganeti)
        bgp_vms = list(self._api.virtualization.virtual_machines.filter(**filters))
        for bgp_vm in bgp_vms:
            hypervisors = self._api.dcim.devices.filter(cluster_id=bgp_vm.cluster.id)
            for hypervisor in hypervisors:
                try:
                    # Get the switch the ganeti host is connected to
                    ganeti_bridge = hypervisor.primary_ip.assigned_object
                    ganeti_uplink = self._api.dcim.interfaces.get(device_id=hypervisor.id, bridge_id=ganeti_bridge.id,
                                                                  type__neq='virtual')
                    switchport = ganeti_uplink.connected_endpoints[0]
                    # We include the server if it's connected to a VC switch or row-wide vlan
                    if switchport.device.virtual_chassis or self.legacy_vlan_name(switchport.untagged_vlan.name):
                        self._bgp_servers.append(bgp_vm)
                except AttributeError:
                    # For example if the server's primary interface is not connected
                    continue
                break

        bgp_devices = list(self._api.dcim.devices.filter(**filters))
        for bgp_device in bgp_devices:
            try:
                switchport = bgp_device.primary_ip.assigned_object.connected_endpoints[0]
                if switchport.device.virtual_chassis or self.legacy_vlan_name(switchport.untagged_vlan.name):
                    self._bgp_servers.append(bgp_device)
            except AttributeError:
                continue
        return self._bgp_servers

    def normalize_bgp_neighbor(self, server) -> dict:
        """Abstraction function to normalize the output of VM and physical servers."""
        bgp_neighbor = {}
        if server.status.value != 'active':
            return {}
        if not server.custom_fields["bgp"]:
            return {}
        server_prefix, sub_count = subn(r'\d{4}', '', server.name)
        if not sub_count:
            logger.error(f"Can't extract the server prefix from {server.name}.")
            return {}
        try:
            bgp_group = HOSTNAMES_TO_GROUPS[server_prefix]['group']
        except KeyError:
            logger.error(f"No BGP group found for {server.name}.")
            return {}
        if 'ipv4_only' in HOSTNAMES_TO_GROUPS[server_prefix]:
            ipv4_only = HOSTNAMES_TO_GROUPS[server_prefix]['ipv4_only']
        else:
            ipv4_only = False
        if server.primary_ip4:
            bgp_neighbor[4] = ip_interface(server.primary_ip4).ip
        if server.primary_ip6 and not ipv4_only:
            bgp_neighbor[6] = ip_interface(server.primary_ip6).ip
        return {'group': bgp_group, 'name': server.name, 'ip_addresses': bgp_neighbor}

    def legacy_vlan_name(self, vlan_name) -> bool:
        """Returns true if vlan name convention is legacy row-wide."""
        split_name = vlan_name.split('-')
        # If no rack location in vlan name or rack location is only 1 char (i.e. row-wide)
        if len(split_name) < 3 or len(split_name[1]) == 1:
            return True
        return False

    def _get_bgp_servers(self) -> dict:
        """Servers that need BGP configured on that router."""
        bgp_neighbors: DefaultDict = defaultdict(dict)
        # For L3 switches iterate over the direcly connected servers
        if self.role.slug in SWITCHES_ROLES and self.device_type.slug in L3_SWITCHES_MODELS:
            ganeti_clusters = set()
            for interface in self.fetch_device_interfaces():
                if interface.connected_endpoints_type != 'dcim.interface':
                    continue
                if not interface.untagged_vlan or self.legacy_vlan_name(interface.untagged_vlan.name):
                    continue
                try:
                    z_device = interface.connected_endpoints[0].device
                    if z_device.rack != self.device_rack:  # Skip links to devices in other racks (i.e. lvs)
                        continue

                    # For Ganeti hosts we need to work out if VMs peer with the switch
                    if z_device.cluster and z_device.cluster not in ganeti_clusters:
                        ganeti_clusters.add(z_device.cluster)
                        hypervisors = self._api.dcim.devices.filter(cluster_id=z_device.cluster.id)
                        hypervisor_racks = set([hypervisor.rack for hypervisor in hypervisors])
                        if len(hypervisor_racks) == 1:
                            # Cluster is only in this rack, VMs should peer with SW not CR
                            bgp_vms = self._api.virtualization.virtual_machines.filter(
                                cluster_id=z_device.cluster.id, cf_bgp=True)
                            for bgp_vm in bgp_vms:
                                neighbor = self.normalize_bgp_neighbor(bgp_vm)
                                if neighbor:
                                    bgp_neighbors[neighbor['group']][neighbor['name']] = neighbor['ip_addresses']

                    neighbor = self.normalize_bgp_neighbor(z_device)
                    if neighbor:
                        bgp_neighbors[neighbor['group']][neighbor['name']] = neighbor['ip_addresses']
                except AttributeError:
                    continue

        elif self.role.slug in ('cr'):
            # For core routers fetch all the servers with the bgp routing custom field then filter them more
            for local_bgp_servers in self.fetch_bgp_servers_l2(self.device_site.slug):
                neighbor = self.normalize_bgp_neighbor(local_bgp_servers)
                if neighbor:
                    bgp_neighbors[neighbor['group']][neighbor['name']] = neighbor['ip_addresses']
        return bgp_neighbors

    def _get_interface_ip_addresses(self, interface_name):
        """Returns IPs belonging to a specific interface."""
        if not self._interface_ip_addresses:
            self._interface_ip_addresses = {}
            for ip_address in self.fetch_device_ip_addresses():
                if ip_address.assigned_object.name not in self._interface_ip_addresses:
                    self._interface_ip_addresses[ip_address.assigned_object.name] = {4: [], 6: []}
                self._interface_ip_addresses[ip_address.assigned_object.name][ip_address.family.value].append(
                    ip_address)
        return self._interface_ip_addresses[interface_name]

    # We have to specify in the Junos chassis stanza how many LAG interfaces we want to provision
    # This function returns how many ae interfaces are configured on the device
    def _get_lag_count(self) -> int:
        """Expose how may LAG interface we need instanciated (includind disabled)."""
        return sum(1 for nb_int in self.fetch_device_interfaces() if nb_int.type.value == 'lag')

    def _get_vrfs(self) -> Optional[defaultdict[defaultdict, defaultdict]]:
        """Gets VRFs that need to be configured by iterating over device interfaces.

        Returns:
            dict: keyed by vrf name, with values of Netbox RD and list of member interfaces

        """
        vrfs: DefaultDict[DefaultDict, defaultdict] = defaultdict(lambda: defaultdict(list))
        for interface in self.fetch_device_interfaces():
            if interface.vrf:
                vrfs[interface.vrf.name]['ints'].append(interface.name)
                vrfs[interface.vrf.name]['id'] = interface.vrf.rd

        return vrfs

    def _get_underlay_ints(self) -> Optional[list[Dict[str, Any]]]:
        """Returns a list of interface names belonging to the underlay that require OSPF.

        Returns:
            list: a list of interface names.
            None: the device is not part of an underlay switch fabric requiring OSFP.

        """
        if 'evpn' not in self._device.config:
            return None

        underlay_ints = []
        for interface in self.fetch_device_interfaces():
            if interface.enabled and interface.count_ipaddresses and not interface.vrf and not interface.mgmt_only:
                underlay_ints.append(interface.name)

        return underlay_ints

    def _get_port_block_speeds(self) -> Optional[Dict[int, int]]:
        """Returns a dict keyed by first port ID of every block of 4 ports and speed for QFX5120-48Y.

        Returns:
            dict: dict keyed by first portd ID of every block of 4 with values representing speed
            None: the device is not a QFX5120-48Y model and we thus don't have to consider ports in groups

        """
        if not self._device.metadata['type'].startswith('qfx5120-48y'):
            return None

        port_blocks = {}
        for interface in self.fetch_device_interfaces():
            if interface.type.value == 'virtual' or interface.type.value == 'lag' or interface.mgmt_only:
                continue

            port = int(interface.name.split(':')[0].split('/')[-1])
            if port >= 48:
                continue

            block = port - (port % 4)
            if interface.type.value.startswith('1000base'):
                speed = 1
            else:
                speed = int(interface.type.value.split('gbase')[0])

            if block not in port_blocks:
                port_blocks[block] = speed
            elif port_blocks[block] != speed:
                # Return none if invalid combo, resulting in generated config without pic 0
                # stanza. This prevents an error in Netbox changing working config.
                return None

        return port_blocks

    def interface_description(self, intconf):
        """Generates interface description based on data in the 'intconf' dict.

        Which gets created by get_link_data() based on various Netbox elements.

        Returns:
            str: interface description for network device, if the intconf data means we
                    don't need a custom description returns an empty string.

        """
        if not intconf['enabled']:
            return "DISABLED"

        if intconf['nb_int_desc']:
            # Custom description from Netbox descrtiption field
            return intconf['nb_int_desc']

        if intconf['circuit_id']:
            # Link connects to a third party circuit
            cct_desc = f"{intconf['circuit_id']} {intconf.get('circuit_desc', '')}".strip()
            if intconf['wmf_z_end']:
                # Typically transport circuit
                return f"{intconf['link_type']}: {intconf['z_dev']}:{intconf['z_int']} ({intconf['provider']}, " \
                    f"{cct_desc}) {{#{intconf['cable_label']}}}"
            # Typically transit circuit
            return f"{intconf['link_type']}: {intconf['provider']} ({cct_desc}) {{#{intconf['cable_label']}}}"

        if intconf['z_dev']:
            # Direct link between two WMF devices
            if intconf['link_type']:
                # Typically 'core' link between two network devices
                return f"{intconf['link_type']}: {intconf['z_dev']}:{intconf['z_int']} {{#{intconf['cable_label']}}}"
            if intconf['cable_label']:
                # Typically server connection
                return f"{intconf['z_dev']} {{#{intconf['cable_label']}}}"
            return f"{intconf['z_dev']}"

        return ''

    def _get_link_data(self, nb_interface):
        """Returns a dict with additional link_data about interface based on multiple factors (remote endpoint,
           Netbox description, etc.)  Logic copied from previous get_int_description() function, but builds a
           dict of parameters instead of a single string.

        Returns:
            dict: dict with the following information relating to the interface:
                    enabled: whether interface is enabled in Netbox
                    nb_int_desc: the interface description field from Netbox (default: None)
                    circuit_id: the circuit id of the connected circuit (default: None)
                    circuit_desc: the circuit description if present (default: empty string)
                    link_type: WMF link 'type' where needed, i.e. Core/Transit/Transpot (default: empty string)
                    z_dev: name of the device the interface connects to (default: empty string)
                    z_int: name of interface where the connection lands on connected device (default: empty string)
                    wmf_z_end: boolean indicating if the z_end device is a node managed by WMF (default: True)
                    upstream_speed: sub-rated peak speed of connected service/circuit if lower than line rate,
                                    taken from the 'upstream_speed' attribute of the cct termination (default: None)

        """
        link_data = {
            "enabled": True,
            "nb_int_desc": None,
            "circuit_id": None,
            "circuit_desc": '',
            "link_type": '',
            "z_dev": '',
            "z_int": '',
            "wmf_z_end": True,
            "upstream_speed": None
        }

        # If the interface is disabled record that and return, other info irrelevant
        if not nb_interface.enabled:
            link_data['enabled'] = False
            return link_data

        # If Netbox has a description record that in link_data
        if nb_interface.description:
            link_data['nb_int_desc'] = nb_interface.description

        # Set a_int to nb interface object of the near-side of the cable
        a_int = None
        if nb_interface.cable:
            a_int = nb_interface
        else:
            # Try to find parent interface based on name
            for nb_int in self.fetch_device_interfaces():
                if '.' in nb_interface.name and nb_interface.name.split('.')[0] == nb_int.name:
                    if nb_int.cable:  # If it's connected, we use that as a_int
                        a_int = nb_int
                    if not link_data['nb_int_desc'] and nb_int.description:
                        # Set sub-int description to parent's netbox description if it has none of its own
                        link_data['nb_int_desc'] = nb_int.description

        # If a_int not set, i.e. no connection, return here as rest of info based on what's connected
        if not a_int:
            return link_data

        # Now we can focus on finding the Z side, and there are different scenarios
        # An interface can be connected (using a cable) to:
        # - A device's interface (easy)
        # - A circuit, itself connected to:
        #    - A device's interface (via another cable)
        #    - A provider
        # - A patch panel (frontport), in that case traverse it first
        link_data['cable_label'] = a_int.cable.label

        # b_int is either the patch panel interface facing out or the initial interface
        # if no patch panel
        if a_int.link_peers_type == 'dcim.frontport' and a_int.link_peers[0].rear_port:
            b_int = a_int.link_peers[0].rear_port
        else:
            # If the patch panel isn't patched through
            b_int = a_int
        # keep dcim.frontport or rear port below for the cases where patch panels are chained.
        # This doesn't handle all the imaginable cases (eg. chaining patch panels and circuits)
        # But handles all our infra cases. To be expanded as needed.
        if b_int.link_peers_type in ('dcim.interface', 'dcim.frontport', 'dcim.rearport'):
            if a_int.connected_endpoints[0].device.virtual_chassis:
                # In VCs we use its virtual name stored in the domain field
                # And only keep the host part
                link_data['z_dev'] = a_int.connected_endpoints[0].device.virtual_chassis.domain.split('.')[0]
            else:
                link_data['z_dev'] = a_int.connected_endpoints[0].device.name
            link_data['z_int'] = a_int.connected_endpoints[0].name
            # Set the link type depending on the other side's type
            core_link_z_dev_types = ['cr', 'asw', 'mr', 'msw', 'pfw', 'cloudsw']

            if a_int.connected_endpoints[0].device.role.slug in core_link_z_dev_types:
                link_data['link_type'] = 'Core'

        if b_int.link_peers_type == 'circuits.circuittermination':
            # Variables needed regardless of the types of circuits
            link_data['link_type'] = b_int.link_peers[0].circuit.type.name
            link_data['provider'] = b_int.link_peers[0].circuit.provider.name
            link_data['circuit_id'] = b_int.link_peers[0].circuit.cid
            link_data['circuit_desc'] = b_int.link_peers[0].circuit.description
            if b_int.link_peers[0].circuit.termination_z:
                link_data['upstream_speed'] = b_int.link_peers[0].circuit.termination_z.upstream_speed

            if not a_int.connected_endpoints or a_int.connected_endpoints_type == 'circuits.providernetwork':
                link_data['wmf_z_end'] = False
            else:
                link_data['z_dev'] = a_int.connected_endpoints[0].device.name
                link_data['z_int'] = a_int.connected_endpoints[0].name

        return link_data

    # If the specific (sub)interface has a non default MTU: return that
    # Else try to find the parent interface MTU
    # Else return None
    def interface_mtu(self, interface_name: str):
        """Return the MTU to use on a given interface."""
        mtu = None
        for nb_int in self.fetch_device_interfaces():
            if nb_int.name == interface_name and nb_int.enabled and nb_int.mtu:
                # Exact match found
                return nb_int.mtu
            if '.' in interface_name and interface_name.split('.')[0] == nb_int.name and nb_int.mtu and nb_int.enabled:
                # Parent interface found and it have an MTU!
                mtu = nb_int.mtu
        # Wait to be done iterating over all the device' interfaces
        # in case an exact match is found after the parent
        return mtu

    def _get_junos_interfaces(self):
        """Expose Netbox interfaces in a way that can be efficiently used by a junos template."""
        jri = {}  # Junos interfaces
        lags_members = defaultdict(list)  # List all the lags to find mixed ones
        ignore_interfaces = ['fxp0-re0', 'fxp0-re1']  # Those are managed in `set groups`
        # Here, unlike for switches, we don't try to group interfaces together but set the proper attributes directly
        for nb_int in self.fetch_device_interfaces():
            # Regarless of what kind of interface it is, set attributes in a Juniper-ish tree
            interface_config = {}
            # TODO skip the ones we don't want
            interface_config['enabled'] = nb_int.enabled
            interface_name = nb_int.name
            if interface_name in ignore_interfaces:
                continue
            # Ignore VC links
            if interface_name.startswith('vcp'):
                continue
            interface_config.update(self._get_link_data(nb_int))

            interface_config['description'] = self.interface_description(interface_config)

            interface_config['type'] = nb_int.type.value

            if nb_int.lag:
                interface_config['lag'] = nb_int.lag.name
                jri[interface_name] = interface_config
                # We store the interfaces contributing to a specific LAG, because if they are of different types,
                # We will later need to apply the "link-speed mixed" config option.
                lags_members[nb_int.lag.name].append(interface_name)
                continue
            # For a LAG, the MTU is set on the ae (virtual) interface not the physical ones (bundle members)
            interface_config['mtu'] = self.interface_mtu(interface_name)

            if nb_int.mac_address:  # Set the MAC if any in netbox
                interface_config['mac'] = nb_int.mac_address

            if nb_int.vrf:  # Set the VRF if any in netbox
                interface_config['vrf'] = nb_int.vrf.name

            if nb_int.mode:  # If the interface is tagged or access
                interface_config['mode'] = nb_int.mode.value
                # We keep the tagged vlan names
                interface_vlans = set()

                # Interface is set to access but doesn't have any vlan configured: set to default
                if interface_config['mode'] == 'access' and not nb_int.untagged_vlan:
                    interface_vlans.add('default')

                # If any tagged interfaces add them to the list
                if nb_int.mode.value == 'tagged':
                    for tagged_vlan in nb_int.tagged_vlans:
                        interface_vlans.add(tagged_vlan.name)

                # If there is an untagged interface, add it to the list
                # Either it's a trunked interface, in that case it will be with the other vlans
                # Or it's an access interface and it will be alone
                if nb_int.untagged_vlan:
                    interface_vlans.add(nb_int.untagged_vlan.name)
                    # Junos needs the native vlan ID and not the name
                    if nb_int.mode.value == 'tagged':
                        interface_config['native_vlan_id'] = nb_int.untagged_vlan.vid

                interface_config['vlans'] = list(interface_vlans)

            # Assign the IPs to the interface if any
            if nb_int.count_ipaddresses > 0:
                # assumes there is v4 for everything
                interface_config['ips'] = {4: {}, 6: {}}
                virt_ips = {}
                int_addresses = self._get_interface_ip_addresses(nb_int.name)
                for address_fam in [4, 6]:
                    for ip_address in int_addresses[address_fam]:
                        if ip_address.role and ip_address.role.value == 'anycast':
                            if len(int_addresses[address_fam]) > 1:
                                # Int must also have a unique IP so we just save this as VGA VIP
                                virt_ips[ip_address.address] = None
                                interface_config['anycast_gw'] = 'vga'
                                continue
                            else:
                                interface_config['anycast_gw'] = 'single'
                        interface_config['ips'][address_fam][ip_interface(ip_address.address)] = {}

                # Assume that interfaces with FHRP IPs will always have "real" IPs
                if nb_int.count_fhrp_groups > 0:
                    for fhrp_assignment in self._api.ipam.fhrp_group_assignments.filter(interface_id=nb_int.id):
                        for ip_addresses in fhrp_assignment.group.ip_addresses:
                            virt_ips[ip_addresses.address] = fhrp_assignment.group.group_id

                # Now assign any VRRP/Anycast IP to the real interface,
                # for that we need to find IPs belonging in the same subnet
                for family, int_ips in interface_config['ips'].items():
                    for int_ip in int_ips.keys():
                        for virt_ip, vrrp_group in virt_ips.items():
                            if ip_interface(virt_ip) in int_ip.network:
                                if vrrp_group or vrrp_group == 0:
                                    interface_config['ips'][family][int_ip]['vrrp'] = {
                                        ip_interface(virt_ip).ip: vrrp_group
                                    }
                                else:
                                    interface_config['ips'][family][int_ip]['anycast'] = ip_interface(virt_ip).ip

            # Now that we have all the interface or sub-interface attribute,
            # we need to nest the sub interfaces in the interfaces when needed
            if '.' in interface_name and interface_name.split('.')[0] in jri:
                # It's a sub-interface and we already have the parent interface, add the sub interface
                parent, sub = interface_name.split('.', 1)
                if 'sub' not in jri[parent]:
                    jri[parent]['sub'] = {}
                jri[parent]['sub'][sub] = interface_config
            # If we have the sub interface but not the parent yet
            elif '.' in interface_name and interface_name.split('.')[0] not in jri:
                parent, sub = interface_name.split('.', 1)
                # Create the parent
                jri[parent] = {'sub': {sub: interface_config}}
            # If we have the parent interface but we found a sub interface earlier
            elif '.' not in interface_name and interface_name in jri:
                # Merge the new stuff with the existing one
                jri[interface_name].update(interface_config)
            # Easiest case, we find the parent interface first
            elif '.' not in interface_name and interface_name not in jri:
                jri[interface_name] = interface_config

            # TODO Remove some Juniper oddities, eg. sub interfaces for LAG members

        # Check if there is any mixed LAG
        for lag, members in lags_members.items():
            if len(set([member.split('-')[0] for member in members])) > 1:
                jri[lag]['mixed'] = True

        return jri
