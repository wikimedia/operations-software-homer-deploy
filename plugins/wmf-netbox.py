"""Netbox gathering functions tailored to the WMF needs."""

import logging

from re import subn

from collections import defaultdict
from typing import Any, DefaultDict, Dict, Optional

from ipaddress import ip_interface, ip_network

from homer.netbox import BaseNetboxDeviceData

logger = logging.getLogger(__name__)

HOSTNAMES_TO_GROUPS: Dict[str, Dict] = {'aux-k8s-ctrl': {'group': 'k8s_aux'},
                                        'aux-k8s-worker': {'group': 'k8s_aux'},
                                        'centrallog': {'group': 'anycast', 'ipv4_only': True},
                                        'cephosd': {'group': 'anycast'},
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
JUNIPER_LEGACY_SW = ('qfx5100-48s-6q', 'ex4600-40f', 'ex4300-48t')
NO_QOS_INTS = ('irb', 'lo', 'fxp', 'em', 'vme')


class NetboxDeviceDataPlugin(BaseNetboxDeviceData):
    """WMF specific class to gather device-specific data dynamically from Netbox."""

    def __init__(self, netbox_api, base_paths, device):
        """Initialize the instance."""
        super().__init__(netbox_api, base_paths, device)
        self._device_ip_addresses = None
        self._interface_ip_addresses = None
        self._bgp_servers = []
        self._junos_interfaces = {}
        self._qos_interfaces = {}
        self.device_id = self._device.metadata['netbox_object'].id
        self.role = self._device.metadata['netbox_object'].role
        self.device_type = self._device.metadata['netbox_object'].device_type
        self.device_rack = self._device.metadata['netbox_object'].rack
        self.device_site = self._device.metadata['netbox_object'].site
        self.virtual_chassis = self._device.metadata['netbox_object'].virtual_chassis

    def fetch_bgp_servers_l2(self, site: str = '') -> list:
        """Fetch VMs or servers on legacy vlans with BGP custom field set that should peer with CRs."""
        if self._bgp_servers:
            return self._bgp_servers

        # We decide if devices should peer with CR based on Vlan membership, we compile
        # in advance the legacy vlans at the site and a list of associated prefixes
        site_vlans = self._api.ipam.vlans.filter(site=site, name__isw=('private1', 'public1'))
        legacy_vlan_ids = [vlan.id for vlan in site_vlans if self.legacy_vlan_name(vlan.name)]
        if not legacy_vlan_ids:
            # Sites with only L3 switches and per-rack vlans
            return self._bgp_servers
        legacy_prefixes_nb = self._api.ipam.prefixes.filter(vlan_id=legacy_vlan_ids)
        legacy_prefixes = [ip_network(legacy_prefix) for legacy_prefix in legacy_prefixes_nb]

        # Build list of active VMs and Hosts at this site with bgp flag enabled
        filters = {'site': site, 'status': 'active', 'role': 'server', 'cf_bgp': True, 'has_primary_ip': True}
        bgp_devices = (list(self._api.dcim.devices.filter(**filters))
                       + list(self._api.virtualization.virtual_machines.filter(**filters)))

        # If they are in a legacy vlan add to the list
        for bgp_device in bgp_devices:
            device_ip = ip_interface(bgp_device.primary_ip)
            for prefix in legacy_prefixes:
                if prefix.version == device_ip.version and prefix.supernet_of(device_ip.network):  # type: ignore
                    self._bgp_servers.append(bgp_device)
                    break

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
        # For L3 switches iterate over the directly connected servers
        if self.role.slug in SWITCHES_ROLES and self.device_type.slug in L3_SWITCHES_MODELS:
            ganeti_clusters = set()
            for interface in self.fetch_device_interfaces():
                if not interface['connected_endpoints']:
                    continue
                if interface['connected_endpoints'][0]['__typename'] != 'InterfaceType':
                    continue
                if not interface['untagged_vlan'] or self.legacy_vlan_name(interface['untagged_vlan']['name']):
                    continue
                try:
                    # Use a Pynetbox query to not overload the GraphQL with extra connected_endpoints data
                    # (cluster ID here, then IPs, custom field, status, etc in normalize_bgp_neighbor)
                    # To be revisited later on as this is sub-optimal
                    z_device = self._api.dcim.devices.get(name=interface['connected_endpoints'][0]['device']['name'])
                    # Skip links to devices in other racks (i.e. lvs)
                    if z_device.rack.name != self.device_rack.name:
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

    # We have to specify in the Junos chassis stanza how many LAG interfaces we want to provision
    # This function returns how many ae interfaces are configured on the device
    def _get_lag_count(self) -> int:
        """Expose how may LAG interface we need instantiated (including disabled)."""
        return sum(1 for nb_int in self.fetch_device_interfaces() if nb_int['type'] == 'lag')

    def _get_vrfs(self) -> Optional[defaultdict[defaultdict, defaultdict]]:
        """Gets VRFs that need to be configured by iterating over device interfaces.

        Returns:
            dict: keyed by vrf name, with values of Netbox RD and list of member interfaces

        """
        vrfs: DefaultDict[DefaultDict, defaultdict] = defaultdict(lambda: defaultdict(list))
        for interface in self.fetch_device_interfaces():
            if interface['vrf']:
                vrfs[interface['vrf']['name']]['ints'].append(interface['name'])
                vrfs[interface['vrf']['name']]['id'] = interface['vrf']['rd']

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
            if (interface['enabled'] and len(interface['ip_addresses']) > 0
               and not interface['vrf'] and not interface['mgmt_only']):
                underlay_ints.append(interface['name'])

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
            if interface['type'] == 'virtual' or interface['type'] == 'lag' or interface['mgmt_only']:
                continue

            port = int(interface['name'].split(':')[0].split('/')[-1])
            if port >= 48:
                continue

            block = port - (port % 4)
            if interface['type'].startswith('1000base'):
                speed = 1
            else:
                speed = int(interface['type'].split('gbase')[0])

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
            # Custom description from Netbox description field
            return intconf['nb_int_desc']

        if intconf['tunnel']:
            if intconf['z_dev']:
                return f"{intconf['link_type']}: " \
                       f"{intconf['z_dev']}:{intconf['z_int']} {intconf['tunnel']['description']}"
            else:
                return intconf['tunnel']['description']
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
                    tunnel: dict with detail of tunnel config params if it is a GRE int
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
            "tunnel": {},
            "upstream_speed": None
        }

        # If the interface is disabled record that and return, other info irrelevant
        if not nb_interface['enabled']:
            link_data['enabled'] = False
            return link_data

        # If Netbox has a description record that in link_data
        if nb_interface['description']:
            link_data['nb_int_desc'] = nb_interface['description']

        if nb_interface['name'].startswith("gr-") or nb_interface['name'].startswith("st"):
            # Get tunnel termination that matches
            tunnel_termination = self._api.vpn.tunnel_terminations.get(termination_id=nb_interface['id'])
            if tunnel_termination is None:
                return link_data
            tunnel = self._api.vpn.tunnels.get(id=tunnel_termination.tunnel.id)
            link_data['tunnel']['source'] = ip_interface(tunnel_termination.outside_ip.address).ip
            link_data['tunnel']['name'] = tunnel.name
            link_data['tunnel']['description'] = tunnel.description
            if tunnel_termination.role.value == "spoke":
                # Right now spoke is only for CF so we can set type based on that
                link_data['wmf_z_end'] = False
                link_data['link_type'] = "Transit-tun"
                link_data['tunnel']['destination'] = ip_interface(
                    tunnel.group.custom_fields['hub_ip']['address']).ip
            else:
                z_end_termination = self._api.vpn.tunnel_terminations.get(tunnel_id=tunnel_termination.tunnel.id,
                                                                          id__n=tunnel_termination.id)
                link_data['tunnel']['destination'] = ip_interface(z_end_termination.outside_ip.address).ip
                link_data['z_dev'] = z_end_termination.termination.device.name
                link_data['z_int'] = z_end_termination.termination.name
                link_data['link_type'] = "Transport-tun"
                if tunnel.encapsulation.value == "ipsec-tunnel":
                    # Route-based IPsec tunnel, include additional properties
                    link_data['link_type'] = "IPsec-tun"
                    link_data['tunnel']['ipsec'] = {}
                    ipsec_profile = self._api.vpn.ipsec_profiles.get(id=tunnel.ipsec_profile.id)
                    # Phase 1 info
                    ike_policy = self._api.vpn.ike_policies.get(id=ipsec_profile.ike_policy.id)
                    ike_proposal = self._api.vpn.ike_proposals.get(ike_policy.proposals[0].id)
                    link_data['tunnel']['ipsec']['ike_proposal'] = {
                        'encryption': ike_proposal.encryption_algorithm.value,
                        'dh_group': ike_proposal.group.value
                    }
                    # Phase 2 info
                    ipsec_policy = self._api.vpn.ipsec_policies.get(id=ipsec_profile.ipsec_policy.id)
                    link_data['tunnel']['ipsec']['pfs_dh_group'] = ipsec_policy.pfs_group.value
                    ipsec_proposal = self._api.vpn.ipsec_proposals.get(ipsec_policy.proposals[0].id)
                    link_data['tunnel']['ipsec']['ipsec_proposal'] = {
                        'encryption': ipsec_proposal.encryption_algorithm.value
                    }
            return link_data

        # Set a_int to nb interface object of the near-side of the cable
        a_int = None
        if nb_interface['cable']:
            a_int = nb_interface
        else:
            # Try to find parent interface based on name
            for nb_int in self.fetch_device_interfaces():
                if '.' in nb_interface['name'] and nb_interface['name'].split('.')[0] == nb_int['name']:
                    if nb_int['cable']:  # If it's connected, we use that as a_int
                        a_int = nb_int
                    if not link_data['nb_int_desc'] and nb_int['description']:
                        # Set sub-int description to parent's netbox description if it has none of its own
                        link_data['nb_int_desc'] = nb_int['description']

        # If a_int not set, i.e. no connection, return here as rest of info based on what's connected
        if not a_int:
            return link_data

        # Safeguard for unterminated cables - T393188 - no need to block, so we act like there is no cable
        if not a_int['link_peers']:
            logger.error("Unterminated cable on %s, please delete the cable - T393188", nb_interface['name'])
            return link_data

        link_data['cable_label'] = a_int['cable']['label']
        # If interface connected to another NB device
        if a_int['connected_endpoints'] and a_int['connected_endpoints'][0]['__typename'] == "InterfaceType":
            b_int = a_int['connected_endpoints'][0]
            link_data['wmf_z_end'] = True
            link_data['z_int'] = b_int['name']
            if b_int['device']['virtual_chassis']:
                link_data['z_dev'] = b_int['device']['virtual_chassis']['domain'].split('.')[0]
            else:
                link_data['z_dev'] = b_int['device']['name']

            # Set link-type to core if it lands on a network device
            core_link_z_dev_types = ['cr', 'asw', 'mr', 'msw', 'pfw', 'cloudsw']
            if b_int['device']['role']['slug'] in core_link_z_dev_types:
                link_data['link_type'] = 'Core'

        if (not a_int['connected_endpoints']
           or a_int['connected_endpoints'][0]['__typename'] == 'ProviderNetworkType'):
            link_data['wmf_z_end'] = False

        circuit = None
        # If interface is directly connected to a circuit
        if a_int['link_peers'][0]['__typename'] == 'CircuitTerminationType':
            circuit = a_int['link_peers'][0]['circuit']
        # If it's connected to a circuit via patch panel
        elif (a_int['link_peers'][0]['__typename'] == 'FrontPortType'
              and a_int['link_peers'][0]['rear_port']['link_peers'][0]['__typename'] == 'CircuitTerminationType'):
            # NOTE: Patch panels could be daisy-chained, which GraphQL won't give us, but we don't have that now
            circuit = a_int['link_peers'][0]['rear_port']['link_peers'][0]['circuit']

        if circuit:
            link_data['link_type'] = circuit['type']['name']
            link_data['provider'] = circuit['provider']['name']
            link_data['circuit_id'] = circuit['cid']
            link_data['circuit_desc'] = circuit['description']
            if circuit['termination_z']:
                link_data['upstream_speed'] = circuit['termination_z']['upstream_speed']

        return link_data

    def _get_qos_interfaces(self) -> dict:
        """ Populates the _qos_interfaces dict based on interfaces dict
            produced by _get_junos_interfaces()

            _qos_interfaces is a dict, keyed by interface name, as with dict elements as follows:
                  dscp_classifier: classifier for ipv4 dscp if required
                  dscp_ip6_classifier: classifier for ipv6 dscp if required
                  shape_rate: overall shaper rate if required
                  units: dict keyed by interface unit number to place above elements when they need to be added there
        """

        if self._qos_interfaces:
            return self._qos_interfaces

        if not self._junos_interfaces:
            self._get_junos_interfaces()

        DSCP_V4_CLASSIFIER = {
            'dscp_classifier': True
        }

        DSCP_DUAL_CLASSIFIER = {
            'dscp_classifier': True,
            'dscp_ip6_classifier': True
        }

        qos_ints: DefaultDict = defaultdict(dict)
        for int_name, int_conf in self._junos_interfaces.items():
            # We ignore certain interfaces
            if int_name.startswith(NO_QOS_INTS) or 'lag' in int_conf or not int_conf['enabled']:
                continue

            # Remaining will all get QoS so create element in dict for it
            qos_ints[int_name]['units'] = {}
            if "description" in int_conf:
                qos_ints[int_name]['description'] = int_conf['description']
            # If circuit has sub-rated peak rate set the shaper to 98% of max
            if "upstream_speed" in int_conf and int_conf['upstream_speed']:
                qos_ints[int_name]['shape_rate'] = int(int_conf['upstream_speed'] * 0.98)

            if self.role.slug in SWITCHES_ROLES:
                # Standard L2 ports facing servers or CRs
                if 'vlans' in int_conf and int_conf['vlans']:
                    if self.device_type.slug in JUNIPER_LEGACY_SW:
                        qos_ints[int_name]['units'][0] = DSCP_V4_CLASSIFIER
                    else:
                        qos_ints[int_name]['units'][0] = DSCP_DUAL_CLASSIFIER

                # L3 routed interfaces or ports with routed sub-interfaces
                elif "ips" in int_conf or "sub" in int_conf:
                    qos_ints[int_name].update(DSCP_V4_CLASSIFIER)

            elif self.role.slug == "cr":
                if "sub" in int_conf:
                    units = int_conf['sub'].keys()
                else:
                    units = [0]

                if "link_type" in int_conf and int_conf['link_type'] in ('Core', 'Transport'):
                    for unit in units:
                        qos_ints[int_name]['units'][unit] = DSCP_DUAL_CLASSIFIER
                elif int_name.startswith("gr-"):
                    for unit, sub_conf in int_conf['sub'].items():
                        if sub_conf['link_type'] == "Transport-tun":
                            qos_ints[int_name]['units'][unit] = DSCP_DUAL_CLASSIFIER

        self._qos_interfaces = qos_ints
        return qos_ints

    # If the specific (sub)interface has a non default MTU: return that
    # Else try to find the parent interface MTU
    # Else return None
    def interface_mtu(self, interface_name: str):
        """Return the MTU to use on a given interface."""
        mtu = None
        for nb_int in self.fetch_device_interfaces():
            if nb_int['name'] == interface_name and nb_int['enabled'] and nb_int['mtu']:
                # Exact match found
                return nb_int['mtu']
            if ('.' in interface_name and interface_name.split('.')[0] == nb_int['name']
               and nb_int['mtu'] and nb_int['enabled']):
                # Parent interface found and it have an MTU!
                mtu = nb_int['mtu']
        # Wait to be done iterating over all the device' interfaces
        # in case an exact match is found after the parent
        return mtu

    def _get_junos_interfaces(self):
        """Expose Netbox interfaces in a way that can be efficiently used by a junos template."""
        if self._junos_interfaces:
            return self._junos_interfaces

        jri = {}  # Junos interfaces
        lags_members = defaultdict(list)  # List all the lags to find mixed ones
        ignore_interfaces = ['fxp0-re0', 'fxp0-re1']  # Those are managed in `set groups`
        # Here, unlike for switches, we don't try to group interfaces together but set the proper attributes directly
        for nb_int in self.fetch_device_interfaces():
            # Regarless of what kind of interface it is, set attributes in a Juniper-ish tree
            interface_config = {}
            # TODO skip the ones we don't want
            interface_config['enabled'] = nb_int['enabled']
            interface_name = nb_int['name']
            if interface_name in ignore_interfaces:
                continue
            # Ignore VC links
            if interface_name.startswith('vcp'):
                continue
            interface_config.update(self._get_link_data(nb_int))

            interface_config['description'] = self.interface_description(interface_config)

            interface_config['type'] = nb_int['type']

            if nb_int['lag']:
                interface_config['lag'] = nb_int['lag']['name']
                jri[interface_name] = interface_config
                # We store the interfaces contributing to a specific LAG, because if they are of different types,
                # We will later need to apply the "link-speed mixed" config option.
                lags_members[nb_int['lag']['name']].append(interface_name)
                continue
            # For a LAG, the MTU is set on the ae (virtual) interface not the physical ones (bundle members)
            interface_config['mtu'] = self.interface_mtu(interface_name)

            if nb_int['mac_address']:  # Set the MAC if any in netbox
                interface_config['mac'] = nb_int['mac_address']

            if nb_int['vrf']:  # Set the VRF if any in netbox
                interface_config['vrf'] = nb_int['vrf']['name']

            if nb_int['mode']:  # If the interface is tagged or access
                interface_config['mode'] = nb_int['mode']
                # We keep the tagged vlan names
                interface_vlans = set()

                # Interface is set to access but doesn't have any vlan configured: set to default
                if interface_config['mode'] == 'access' and not nb_int['untagged_vlan']:
                    interface_vlans.add('default')

                # If any tagged interfaces add them to the list
                if nb_int['mode'] == 'tagged':
                    for tagged_vlan in nb_int['tagged_vlans']:
                        interface_vlans.add(tagged_vlan['name'])

                # If there is an untagged interface, add it to the list
                # Either it's a trunked interface, in that case it will be with the other vlans
                # Or it's an access interface and it will be alone
                if nb_int['untagged_vlan']:
                    interface_vlans.add(nb_int['untagged_vlan']['name'])
                    # Junos needs the native vlan ID and not the name
                    if nb_int['mode'] == 'tagged':
                        interface_config['native_vlan_id'] = nb_int['untagged_vlan']['vid']

                interface_config['vlans'] = list(interface_vlans)

            # Assign the IPs to the interface if any
            if len(nb_int['ip_addresses']) > 0:
                # assumes there is v4 for everything
                interface_config['ips'] = {4: {}, 6: {}}
                virt_ips = {}
                for ip_address in nb_int['ip_addresses']:
                    if ip_address['role'] == 'anycast':
                        count_ips_family = sum(1 for ip in nb_int['ip_addresses']
                                               if ip["family"]["value"] == ip_address["family"]["value"])
                        if count_ips_family > 1:
                            # Int must also have a unique IP so we just save this as VGA VIP
                            virt_ips[ip_address['address']] = None
                            interface_config['anycast_gw'] = 'vga'
                            continue
                        else:
                            interface_config['anycast_gw'] = 'single'
                    interface_config['ips'][ip_address["family"]["value"]][ip_interface(ip_address['address'])] = {}

                # Assume that interfaces with FHRP IPs will always have "real" IPs
                # TODO: perf regression as we now run a pynetbox query for each interface that have an IP
                for fhrp_assignment in self._api.ipam.fhrp_group_assignments.filter(interface_id=nb_int['id']):
                    for ip_addresses in fhrp_assignment.group.ip_addresses:
                        virt_ips[ip_addresses.address] = {
                            'group': fhrp_assignment.group.group_id,
                            'priority': fhrp_assignment.priority
                        }

                # Now assign any VRRP/Anycast IP to the real interface,
                # for that we need to find IPs belonging in the same subnet
                for family, int_ips in interface_config['ips'].items():
                    for int_ip in int_ips.keys():
                        for virt_ip, vrrp_data in virt_ips.items():
                            if ip_interface(virt_ip) in int_ip.network:
                                if vrrp_data is None:
                                    # Anycast GW Interface so no VRRP info
                                    interface_config['ips'][family][int_ip]['anycast'] = ip_interface(virt_ip).ip
                                else:
                                    interface_config['ips'][family][int_ip]['vrrp'] = {
                                        ip_interface(virt_ip).ip: vrrp_data
                                    }

            # Now that we have all the interface attributes, we add it to the jri dict,
            # either directly or as a 'sub' to the parent int
            if '.' in interface_name:
                # Sub-interface - add sub to existing parent or create it with sub
                parent, sub = interface_name.split('.', 1)
                if parent in jri:
                    if 'sub' not in jri[parent]:
                        jri[parent]['sub'] = {}
                    jri[parent]['sub'][sub] = interface_config
                else:
                    jri[parent] = {'sub': {sub: interface_config}, 'enabled': True}
            else:
                # Physical-int - merge data with existing or add as new element
                try:
                    jri[interface_name].update(interface_config)
                except KeyError:
                    jri[interface_name] = interface_config

            # TODO Remove some Juniper oddities, eg. sub interfaces for LAG members

        # Process LAGs
        for lag, members in lags_members.items():
            # If mixed-speed ints (based on int name) set mode to mixed
            if len(set([member.split('-')[0] for member in members])) > 1:
                jri[lag]['mixed'] = True
            # Copy 'link_type' parameter from member to LAG itself
            if not jri[lag]['link_type']:
                for member in members:
                    if jri[member]['link_type']:
                        jri[lag]['link_type'] = jri[member]['link_type']
                        break

        self._junos_interfaces = jri
        return jri
