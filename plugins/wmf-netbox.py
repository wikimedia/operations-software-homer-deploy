"""Netbox gathering functions tailored to the WMF needs"""

from collections import defaultdict
from typing import Any, Dict, List, Optional

from ipaddress import ip_interface

from homer.netbox import BaseNetboxDeviceData


class NetboxDeviceDataPlugin(BaseNetboxDeviceData):  # pylint: disable=too-many-ancestors
    """WMF specific class to gather device-specific data dynamically from Netbox."""

    def __init__(self, netbox_api, device):
        """Initialize the instance."""
        super().__init__(netbox_api, device)
        self._device_interfaces = None
        self._device_ip_addresses = None
        self._circuit_terminations = {}
        self._device_circuits = None
        self.device_id = self._device.metadata['netbox_object'].id

        if 'evpn' in self._device.config:
            self._evpn = self._device.config['evpn']
        else:
            self._evpn = False

    def fetch_device_interfaces(self):
        """Fetch interfaces from Netbox."""
        if not self._device_interfaces:
            self._device_interfaces = self._api.dcim.interfaces.filter(device_id=self.device_id)
        return self._device_interfaces

    def fetch_device_ip_addresses(self):
        """Fetch IPs from Netbox."""
        if not self._device_ip_addresses:
            self._device_ip_addresses = self._api.ipam.ip_addresses.filter(device_id=self.device_id)
        return self._device_ip_addresses

    def fetch_circuit_terminations(self, circuit_id: int):
        """Fetch circuit terminations from Netbox."""
        if circuit_id not in self._circuit_terminations:
            self._circuit_terminations[circuit_id] = self._api.circuits.circuit_terminations.filter(circuit_id=circuit_id)
        return self._circuit_terminations[circuit_id]

    def _get_disabled(self) -> Dict[str, List[str]]:
        """Expose disabled interfaces in a way that can be efficiently used by the templates."""
        # Junos doesn't accept all kind of interfaces as disabled. Some filtering is needed.

        # Snowflake disabled interface are interfaces that don't fit in interface-range
        SNOWFLAKE_INTERFACE_TYPES = ['lag']
        jdi = {'regular': [], 'snowflakes': []}  # junos disabled interfaces
        for nb_int in self.fetch_device_interfaces():
            if '.' in nb_int.name:  # Can't set sub-interfaces to disabled
                continue
            if nb_int.enabled:  # Ignore enabled interfaces
                continue
            if nb_int.mgmt_only:  # Mgmt interfaces need their own config stanza
                jdi['snowflakes'].append(nb_int.name)
            elif nb_int.type.value in SNOWFLAKE_INTERFACE_TYPES:
                jdi['snowflakes'].append(nb_int.name)
            elif ":" in nb_int.name: # Breakout cables need their own config stanza
                jdi['snowflakes'].append(nb_int.name)
            else:  # Everything else are regular interfaces
                jdi['regular'].append(nb_int.name)
        return jdi

    def _get_junos_router_interfaces(self):
        """Expose Netbox interfaces in a way that can be efficiently used by a junos router template."""
        jri = {}  # Junos router interfaces
        lags_members = defaultdict(list)  # List all the lags to find mixed ones
        ignore_interfaces = ['fxp0-re0', 'fxp0-re1']  # Those are managed in `set groups`
        # Here, unlike for switches, we don't try to group interfaces together but set the proper attributes directly
        for nb_int in self.fetch_device_interfaces():
            # TODO skip the ones we don't want
            if not nb_int.enabled:
                continue
            interface_name = nb_int.name
            if interface_name in ignore_interfaces:
                continue
            # Ignore VC links
            if interface_name.startswith('vcp'):
                continue
            # Regarless of what kind of interface it is, set attributes in a Juniper-ish tree
            interface_config = {}

            interface_config['description'] = self.interface_description(interface_name)
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

            # Assign the IPs to the interface if any
            if nb_int.count_ipaddresses > 0:
                # assumes there is v4 for everything
                interface_config['ips'] = {4: {}, 6: {}}

                virt_ips = {}
                for ip_address in self.fetch_device_ip_addresses():
                    if ip_address.assigned_object.name != interface_name:
                        # Only care about the IPs for our interface
                        continue
                    if ip_address.role:
                        # If we're dealing with a virtual IP, keep it on the side to later on make it a child
                        # of the real interface IP
                        if ip_address.role.value == 'vrrp':
                            virt_ips[ip_address.address] = ip_address.custom_fields['group_id']
                            continue
                        if ip_address.role.value == 'anycast':
                            virt_ips[ip_address.address] = None
                            continue
                    interface_config['ips'][ip_address.family.value][ip_interface(ip_address.address)] = {}

                # Now assign any VRRP/Anycast IP to the real interface,
                # for that we need to find IPs belonging in the same subnet
                for family, int_ips in interface_config['ips'].items():
                    for int_ip in int_ips.keys():
                        for virt_ip, vrrp_group in virt_ips.items():
                            if ip_interface(virt_ip) in int_ip.network:
                                if vrrp_group or vrrp_group == 0:
                                    interface_config['ips'][family][int_ip]['vrrp'] = {ip_interface(virt_ip).ip: vrrp_group}
                                else:
                                    interface_config['ips'][family][int_ip]['anycast'] = ip_interface(virt_ip).ip
                                    interface_config['anycast_gw'] = True

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

    def _get_junos_switch_interfaces(self) -> Dict[str, Dict]:
        """Expose Netbox interfaces in a way that can be efficiently used by a junos switch template."""
        jsi = {}  # Junos switch interfaces
        jsi['access_only'] = {}
        jsi['description_only'] = {}
        jsi['tagged'] = {}
        jsi['misc'] = {}
        for nb_int in self.fetch_device_interfaces():
            interface_name = nb_int.name
            # TODO skip the ones we don't want
            if not nb_int.enabled:
                continue
            # Start by the easy ones, access only
            # Tagged    Untagged
            # False     True
            if str(nb_int.mode) == 'Access':
                if nb_int.untagged_vlan:
                    vlan_name = nb_int.untagged_vlan.name
                else:
                    vlan_name = 'default'
                # Create the matching key if not already there
                if vlan_name not in jsi['access_only']:
                    jsi['access_only'][vlan_name] = []
                jsi['access_only'][vlan_name].append(interface_name)

                # Acces only interfaces are present twice in the Junos config:
                # Once groupped by their vlan in interface-range
                # Once on their own with only the description
                jsi['description_only'][interface_name] = self.interface_description(nb_int.name)

            # Tagged    Untagged
            # True      False
            # True      True
            # Trunk interface with or without a native vlan
            elif nb_int.tagged_vlans:
                interface_config = {}
                interface_config['name'] = interface_name
                interface_config['description'] = self.interface_description(nb_int.name)
                interface_config['vlan_members'] = []
                # Populate the above list
                # tagged_vlans is never None thanks to the elif condition
                for tagged_vlan in nb_int.tagged_vlans:
                    interface_config['vlan_members'].append(tagged_vlan.name)
                if nb_int.untagged_vlan:  # This one can be None
                    # Junos rquires the native vlan to be in the trunk list
                    interface_config['vlan_members'].append(nb_int.untagged_vlan.name)
                    # Junos needs the native vlan ID and not name
                    interface_config['native_vlan_id'] = nb_int.untagged_vlan.vid
                interface_config['mtu'] = self.interface_mtu(interface_name)
                jsi['tagged'][interface_name] = interface_config

            # Tagged    Untagged
            # False     False
            # This match all the junk
            else:
                interface_config = {}
                interface_config['description'] = self.interface_description(interface_name)
                if nb_int.lag:
                    interface_config['lag'] = nb_int.lag.name
                    jsi['misc'][interface_name] = interface_config
                    continue  # A LAG parent can't have an IP
                # Check if an IP is assigned to that interface have an IP
                for ip_address in self.fetch_device_ip_addresses():
                    # IPs are only configured on sub-interfaces
                    # A bit of a dirty hack just for our infra
                    # Check if the current interface have a subinterface with an IP
                    if ip_address.assigned_object.name == interface_name:
                        interface_config['address'] = ip_address.address
                        jsi['misc'][interface_name] = interface_config
        return jsi

    # We have to specify in the Junos chassis stanza how many LAG interfaces we want to provision
    # This function returns how many ae interfaces are configured on the device
    def _get_lag_count(self) -> int:
        """Expose how may LAG interface we need instanciated (includind disabled)."""
        return sum(1 for nb_int in self.fetch_device_interfaces() if nb_int.type.value == 'lag')

    # If the specific (sub)interface has a description: return that
    # Else try to find the parent interface description
    # Else generate the description based on cabling (remove host, etc) of the parent interface
    # Else return empty string

    def _get_underlay_ints(self) -> Optional[Dict[str, Dict[str, Any]]]:
        """Returns a list of interface names belonging to the underlay that require OSPF.

        Returns:
            list: a list of interface names.
            None: the device is not part of an underlay switch fabric requiring OSFP.

        """
        if 'evpn' not in self._device.config:
            return None

        underlay_ints = {}
        for interface in self.fetch_device_interfaces():
            ips = self._api.ipam.ip_addresses.filter(interface_id=interface.id)
            if ips and interface.connected_endpoint:
                if interface.connected_endpoint.device.device_role.slug == 'asw':
                    far_side_loopback_int = self._api.dcim.interfaces.get(
                        device_id=interface.connected_endpoint.device.id,
                        name="lo0")
                    far_side_loopback_ip = self._api.ipam.ip_addresses.get(interface_id=far_side_loopback_int.id)
                    underlay_ints[interface.name] = {
                        "device": interface.connected_endpoint.device.name,
                        "ip": ip_interface(far_side_loopback_ip).ip
                    }

        return underlay_ints

    def interface_description(self, interface_name: str):
        """Generate an interface description based on multiple factors (remote endpoint, Netbox description, etc)."""
        description = None
        prefix = ''
        a_int = None  # A (local) side interface of a cable
        for nb_int in self.fetch_device_interfaces():
            if nb_int.name == interface_name:  # If we have an exact interface match
                if not nb_int.enabled:
                    prefix = 'DISABLED '
                if nb_int.description:  # Return description if any
                    return prefix + nb_int.description
                elif nb_int.cable:  # Or if it's connected, save the interface for later
                    a_int = nb_int
                    break
            elif '.' in interface_name and interface_name.split('.')[0] == nb_int.name:  # Parent interface found
                if nb_int.description:  # and it has a description!
                    description = nb_int.description
                elif nb_int.cable:  # If it's connected, store it for later
                    a_int = nb_int
        # Only return the parent description once we're sure there is no exact match with a description
        if description:
            return prefix + description

        # If really found nothing, return it
        if not a_int:
            return prefix.strip()

        # Now we can focus on finding the Z side, and there are different scenarios
        # An interface can be connected (using a cable) to:
        # - A device's interface (easy)
        # - A circuit, itself connected to:
        #    - A device's interface (via another cable)
        #    - A provider
        cable_label = a_int.cable.label
        # We get the list of circuits connected to the device, key = local interface name
        if a_int.link_peer_type in ('dcim.interface', 'dcim.frontport'):
            if a_int.link_peer.device.virtual_chassis:
                # In VCs we use its virtual name stored in the domain field
                # And only keep the host part
                z_dev = a_int.link_peer.device.virtual_chassis.domain.split('.')[0]
            else:
                z_dev = a_int.link_peer.device.name
            z_int = a_int.link_peer.name
            # Set the link type depending on the other side's type
            core_link_z_dev_types = ['cr', 'asw', 'mr', 'msw', 'pfw', 'cloudsw']

            if a_int.link_peer.device.device_role.slug in core_link_z_dev_types:
                link_type = 'Core: '
            else:
                link_type = ''
                z_int = ''  # See T277006
            if cable_label:
                cable_label = f" {{#{cable_label}}}"
            if z_int:
                z_int = f":{z_int}"
            description = f"{link_type}{z_dev}{z_int}{cable_label}"
            return prefix + description

        elif a_int.link_peer_type == 'circuits.circuittermination':
            # Constant variables regadless of the # of terminations
            link_type = a_int.link_peer.circuit.type.name
            provider = a_int.link_peer.circuit.provider.name
            cid = a_int.link_peer.circuit.cid
            circuit_description = a_int.link_peer.circuit.description
            terminations = self.fetch_circuit_terminations(a_int.link_peer.circuit.id)
            details = []
            if cid:
                details.append(cid)
            if circuit_description:
                details.append(circuit_description)
            # A circuit can have 0, 1, or 2 terminations
            # 0 is not possible here as we already have a_dev/a_int
            # 1 is when we don't care about the Z (remote) side' device (eg. transits, peering)
            # 2 is when we manage both sides (eg. transport)
            if len(terminations) == 1:
                description = f"{link_type}: {provider} ({', '.join(details)}) {{#{cable_label}}}"
            elif len(terminations) == 2:
                if a_int.link_peer_type == 'dcim.interface':
                    vc = a_int.link_peer.device.virtual_chassis
                    link_peer = a_int.link_peer
                else:
                    for termination in terminations:  # Find the Z side
                        # Check if the (local or remote) side is a virtual chassis
                        vc = termination.link_peer.device.virtual_chassis
                        link_peer = termination.link_peer
                        # If the side is a VC use the master ID to make sure it's not our local side
                        # Otherwise use the regular endpoint device_id
                        if ((vc and (vc.master.id != self.device_id))
                           or (not vc and (link_peer.device.id != self.device_id))):
                            # Exit the loop when we find the good termination
                            break
                if vc:
                    # Same as previously, if VC get the hostname from the domain field
                    z_dev = vc.domain.split('.')[0]
                else:
                    z_dev = link_peer.device.name
                z_int = link_peer.name

                description = f"{link_type}: {z_dev}:{z_int} ({provider}, {', '.join(details)}) {{#{cable_label}}}"
            return prefix + description

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

            interface_config['description'] = self.interface_description(interface_name)
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
                for ip_address in self.fetch_device_ip_addresses():
                    if ip_address.assigned_object.name != interface_name:
                        # Only care about the IPs for our interface
                        continue
                    if ip_address.role:
                        # If we're dealing with a virtual IP, keep it on the side to later on make it a child
                        # of the real interface IP
                        if ip_address.role.value == 'vrrp':
                            virt_ips[ip_address.address] = ip_address.custom_fields['group_id']
                            continue
                        if ip_address.role.value == 'anycast':
                            virt_ips[ip_address.address] = None
                            continue
                    interface_config['ips'][ip_address.family.value][ip_interface(ip_address.address)] = {}

                # Now assign any VRRP/Anycast IP to the real interface,
                # for that we need to find IPs belonging in the same subnet
                for family, int_ips in interface_config['ips'].items():
                    for int_ip in int_ips.keys():
                        for virt_ip, vrrp_group in virt_ips.items():
                            if ip_interface(virt_ip) in int_ip.network:
                                if vrrp_group or vrrp_group == 0:
                                    interface_config['ips'][family][int_ip]['vrrp'] = {ip_interface(virt_ip).ip: vrrp_group}
                                else:
                                    interface_config['ips'][family][int_ip]['anycast'] = ip_interface(virt_ip).ip
                                    interface_config['anycast_gw'] = True

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
