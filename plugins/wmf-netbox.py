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
        description = ''
        a_int = None  # A (local) side interface of a cable
        for nb_int in self.fetch_device_interfaces():
            if nb_int.name == interface_name:  # If we have an exact interface match
                if not nb_int.enabled:
                    return 'DISABLED'
                if nb_int.description:  # Return description if any
                    return nb_int.description
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
            return description

        # If really found nothing, return it
        if not a_int:
            return ''

        # Now we can focus on finding the Z side, and there are different scenarios
        # An interface can be connected (using a cable) to:
        # - A device's interface (easy)
        # - A circuit, itself connected to:
        #    - A device's interface (via another cable)
        #    - A provider
        # - A patch panel (frontport), in that case traverse it first
        cable_label = a_int.cable.label

        # b_int is either the patch panel interface facing out or the initial interface
        # if no patch panel
        if a_int.link_peer_type == 'dcim.frontport' and a_int.link_peer.rear_port:
            b_int = a_int.link_peer.rear_port
        else:
            # If the patch panel isn't patched through
            b_int = a_int
        # keep dcim.frontport or rear port below for the cases where patch panels are chained.
        # This doesn't handle all the imaginable cases (eg. chaining patch panels and circuits)
        # But handles all our infra cases. To be expanded as needed.
        if b_int.link_peer_type in ('dcim.interface', 'dcim.frontport', 'dcim.rearport'):
            if a_int.connected_endpoint.device.virtual_chassis:
                # In VCs we use its virtual name stored in the domain field
                # And only keep the host part
                z_dev = a_int.connected_endpoint.device.virtual_chassis.domain.split('.')[0]
            else:
                z_dev = a_int.connected_endpoint.device.name
            z_int = a_int.connected_endpoint.name
            # Set the link type depending on the other side's type
            core_link_z_dev_types = ['cr', 'asw', 'mr', 'msw', 'pfw', 'cloudsw']

            if a_int.connected_endpoint.device.device_role.slug in core_link_z_dev_types:
                link_type = 'Core: '
            else:
                link_type = ''
                z_int = ''  # See T277006
            if cable_label:
                cable_label = f" {{#{cable_label}}}"
            if z_int:
                z_int = f":{z_int}"
            description = f"{link_type}{z_dev}{z_int}{cable_label}"
        if b_int.link_peer_type == 'circuits.circuittermination':
            # Variables needed regardless of the types of circuits
            link_type = b_int.link_peer.circuit.type.name
            provider = b_int.link_peer.circuit.provider.name
            cid = b_int.link_peer.circuit.cid
            circuit_description = b_int.link_peer.circuit.description
            details = []
            if cid:
                details.append(cid)
            if circuit_description:
                details.append(circuit_description)

            # If the circuit doesn't have an endpoint or is connected to a provider network
            # Which mean we don't manage the remote side
            # note that only far ends of a path have "connected_endpoint" so using it on "a_int"
            if not a_int.connected_endpoint or a_int.connected_endpoint_type == 'circuits.providernetwork':
                description = f"{link_type}: {provider} ({', '.join(details)}) {{#{cable_label}}}"

            else:  # We manage the remote side
                z_dev = a_int.connected_endpoint.device.name
                z_int = a_int.connected_endpoint.name
                description = f"{link_type}: {z_dev}:{z_int} ({provider}, {', '.join(details)}) {{#{cable_label}}}"

        return description


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
