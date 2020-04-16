"""Netbox gathering functions tailored to the WMF needs"""
from typing import Dict, List

from homer.netbox import BaseNetboxDeviceData


class NetboxDeviceDataPlugin(BaseNetboxDeviceData):  # pylint: disable=too-many-ancestors
    """WMF specific class to gather device-specific data dynamically from Netbox."""

    def __init__(self, netbox_api, device):
        """Initialize the instance."""
        super().__init__(netbox_api, device)
        self._device_interfaces = None
        self._device_ip_addresses = None
        self._circuit_terminations = {}
        self.device_id = self._device.metadata['netbox_object'].id

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
            else:  # Everything else are regular interfaces
                jdi['regular'].append(nb_int.name)
        return jdi

    def _get_junos_switch_interfaces(self) -> Dict[str, Dict]:
        """Expose Netbox interfaces in a way that can be efficiently used by a junos switch template."""
        jsi = {}  # Junos switch interfaces
        jsi['access_only'] = {}
        jsi['description_only'] = {}
        jsi['tagged'] = {}
        jsi['misc'] = {}
        for nb_int in self.fetch_device_interfaces():
            # TODO skip the ones we don't want
            if not nb_int.enabled:
                continue
            # Start by the easy ones, access only
            # Tagged    Untagged
            # False     True
            if not nb_int.tagged_vlans and nb_int.untagged_vlan:
                # Because of how Juniper expose its data, the vlans are applied to the "sub" interface
                # But we only need the "parent" interface name, so we remove anything like ".0"
                interface_name = nb_int.name.split('.')[0]
                vlan_name = nb_int.untagged_vlan.name
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
                interface_name = nb_int.name.split('.')[0]
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
                interface_config['mtu'] = self.interface_mtu(nb_int.name)
                jsi['tagged'][interface_name] = interface_config

            # Tagged    Untagged
            # False     False
            # This match all the junk
            else:
                interface_config = {}
                interface_config['description'] = self.interface_description(nb_int.name)
                if nb_int.lag:
                    interface_config['lag'] = nb_int.lag.name
                    jsi['misc'][nb_int.name] = interface_config
                    continue  # A LAG parent can't have an IP
                # Check if the interface have an IP
                for ip_address in self.fetch_device_ip_addresses():
                    # IPs are only configured on sub-interfaces
                    # A bit of a dirty hack just for our infra
                    # Check if the current interface have a subinterface with an IP
                    if ip_address.interface.name == nb_int.name + '.0':
                        interface_config['address'] = ip_address.address
                        jsi['misc'][nb_int.name] = interface_config
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
    def interface_description(self, interface_name: str):
        """Generate an interface description based on multiple factors (remote endpoint, Netbox description, etc)."""
        description = None
        a_int = None  # A (local) side interface of a cable
        for nb_int in self.fetch_device_interfaces():
            if nb_int.name == interface_name:  # If we have an exact interface match
                if nb_int.description:  # Return description if any
                    return nb_int.description
                elif nb_int.cable:  # Or if it's connected, save the interface for later
                    a_int = nb_int
                    break
            elif '.' in interface_name and interface_name.split('.')[0] == nb_int.name:  # Parent interface found
                if nb_int.description:  # and it have a description!
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
        cable_label = a_int.cable.label
        if a_int.connected_endpoint_type == 'dcim.interface':
            if a_int.connected_endpoint.device.virtual_chassis:
                # In VCs we use its virtual name stored in the domain field
                # And only keep the host part
                z_dev = a_int.connected_endpoint.device.virtual_chassis.domain.split('.')[0]
            else:
                z_dev = a_int.connected_endpoint.device.name
            z_int = a_int.connected_endpoint.name
            # Set the link type depending on the other side's type
            core_link_z_dev_types = ['cr', 'asw', 'mr', 'msw', 'pfw']
            if a_int.connected_endpoint.device.device_role.slug in core_link_z_dev_types:
                type = 'Core: '
            else:
                type = ''
            description = "{type}{z_dev}:{z_int} {{#{cable_label}}}".format(
                type=type,
                z_dev=z_dev,
                z_int=z_int,
                cable_label=cable_label)  # TODO FIX
            return description

        elif a_int.connected_endpoint_type == 'circuits.circuittermination':
            # Constant variables regadless of the # of terminations
            type = a_int.connected_endpoint.circuit.type.name
            provider = a_int.connected_endpoint.circuit.provider.name
            cid = a_int.connected_endpoint.circuit.cid
            circuit_description = a_int.connected_endpoint.circuit.description
            terminations = self.fetch_circuit_terminations(a_int.connected_endpoint.circuit.id)
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
                description = "{type}: {provider} [{details}] {{#{cable_label}}}".format(type=type,
                                                                                         provider=provider,
                                                                                         details=', '.join(details),
                                                                                         cable_label=cable_label)

            elif len(terminations) == 2:
                for termination in terminations:  # Find the Z side
                    # Check if the (local or remote) side is a virtual chassis
                    vc = termination.connected_endpoint.device.virtual_chassis
                    # If the side is a VC use the master ID to make sure it's not our local side
                    # Otherwise use the regular endpoint device_id
                    if ((vc and (vc.master.id != self.device_id))
                       or (not vc and (termination.connected_endpoint.device.id != self.device_id))):
                        if vc:
                            # Same as previously, if VC get the hostname from the domain field
                            z_dev = vc.domain.split('.')[0]
                        else:
                            z_dev = termination.connected_endpoint.device.name
                        z_int = termination.connected_endpoint.name
                description = "{type}: {z_dev}:{z_int} ({provider}, {details}) {{#{cable_label}}}".format(
                  type=type,
                  z_dev=z_dev,
                  z_int=z_int,
                  provider=provider,
                  details=', '.join(details),
                  cable_label=cable_label)
            return description

    # If the specific (sub)interface has a non default MTU: return that
    # Else try to find the parent interface MTU
    # Else return None
    def interface_mtu(self, interface_name: str):
        """Return the MTU to use on a given interface."""
        mtu = None
        for nb_int in self.fetch_device_interfaces():
            if nb_int.name == interface_name and nb_int.mtu:
                # Exact match found
                return nb_int.mtu
            if '.' in interface_name and interface_name.split('.')[0] == nb_int.name and nb_int.mtu:
                # Parent interface found and it have an MTU!
                mtu = nb_int.mtu
        # Wait to be done iterating over all the device' interfaces
        return mtu
