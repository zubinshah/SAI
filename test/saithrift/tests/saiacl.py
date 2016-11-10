# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift SAI interface ACL tests
"""

from switch import *
import sai_base_test


@group('acl')
class IPAclTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        """
        Deny packets from a IPv4 Source address.
        Steps:
        1. create two router interfaces
        2. create route
        3. send packet from port2 to port1 and verify packet on port1
        4. create ACL table, entry and bind to port1 OID
        5. send packet from port2 to port1 and verify that packet from a IPv4 Source address is not received on port1
        6. clean up.
        """
        print
        print "Sending packet port 2 -> port 1 (192.168.0.1 -> 10.10.10.1 [id = 105])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src=router_mac,
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)

        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

        # setup mandatory attributes on creation ACL table
        stage = SAI_ACL_STAGE_INGRESS
        bind_point = SAI_ACL_BIND_POINT_PORT
        table_priority = SAI_SWITCH_ATTR_ACL_TABLE_MINIMUM_PRIORITY

        # setup ACL to block based on Source IP
        entry_priority = SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = None
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = "192.168.0.1"
        ip_src_mask = "255.255.255.0"
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        ingress_mirror_id = None
        egress_mirror_id = None

        # setup bind object id
        bind_to_ingress_port_id_list = [port1]
        bind_to_egress_port_id_list = None
        bind_to_ingress_lag_id_list = None
        bind_to_egress_lag_id_list = None
        bind_to_ingress_vlan_id_list = None
        bind_to_egress_vlan_id_list = None
        bind_to_ingress_rif_id_list = None
        bind_to_egress_rif_id_list = None
        bind_to_ingress_switch_id_list = None
        bind_to_egress_switch_id_list = None

        acl_table_id = sai_thrift_create_acl_table(self.client, addr_family,
                                                   stage,
                                                   bind_point,
                                                   table_priority,
                                                   mac_src, mac_dst,
                                                   ip_src, ip_dst,
                                                   ip_proto,
                                                   in_ports, out_ports,
                                                   in_port, out_port)

        acl_entry_id = sai_thrift_create_acl_entry(self.client, acl_table_id,
                                                   addr_family,
                                                   entry_priority,
                                                   action,
                                                   mac_src, mac_src_mask,
                                                   mac_dst, mac_dst_mask,
                                                   ip_src, ip_src_mask,
                                                   ip_dst, ip_dst_mask,
                                                   ip_proto,
                                                   in_ports, out_ports,
                                                   in_port, out_port,
                                                   ingress_mirror_id,
                                                   egress_mirror_id)

        acl_bind_object_id = sai_thrift_acl_bind_to_object(self.client, acl_table_id,
                                                           bind_to_ingress_port_id_list,
                                                           bind_to_egress_port_id_list,
                                                           bind_to_ingress_lag_id_list,
                                                           bind_to_egress_lag_id_list,
                                                           bind_to_ingress_vlan_id_list,
                                                           bind_to_egress_vlan_id_list,
                                                           bind_to_ingress_rif_id_list,
                                                           bind_to_egress_rif_id_list,
                                                           bind_to_ingress_switch_id_list,
                                                           bind_to_egress_switch_id_list)

        try:
            # send the same packet
            send_packet(self, 2, str(pkt))
            # ensure packet is dropped
            # check for absence of packet here!
            verify_no_packet(self, exp_pkt, 1)
        finally:
            # delete ACL
            self.client.sai_thrift_acl_unbind_from_object(acl_bind_object_id)
            self.client.sai_thrift_delete_acl_entry(acl_entry_id)
            self.client.sai_thrift_delete_acl_table(acl_table_id)

            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

@group('acl')
class MACSrcAclTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        """
        Deny packets from a MAC Source address.
        Steps:
        1. create two router interfaces
        2. create route
        3. send packet from port2 to port1 and verify packet on port1
        4. create ACL table, entry and bind to port1 OID
        5. send packet from port2 to port1 and verify that packet from a MAC Source address is not received on port1
        6. clean up.
        """
        print
        print "Sending packet port 2 -> port 1 (192.168.0.1 -> 10.10.10.1 [id = 105])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst=router_mac,
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                    eth_src=router_mac,
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.0.1',
                                    ip_id=105,
                                    ip_ttl=63)

        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

        # setup mandatory attributes on creation ACL table
        stage = SAI_ACL_STAGE_INGRESS
        bind_point = SAI_ACL_BIND_POINT_PORT
        table_priority = SAI_SWITCH_ATTR_ACL_TABLE_MINIMUM_PRIORITY

        # setup ACL to block based on Source MAC
        entry_priority = SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY
        action = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]
        mac_src = '00:22:22:22:22:22'
        mac_dst = None
        mac_src_mask = None
        mac_dst_mask = None
        ip_src = None
        ip_src_mask = None
        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = None
        ingress_mirror_id = None
        egress_mirror_id = None

        # setup bind object id
        bind_to_ingress_port_id_list = [port1]
        bind_to_egress_port_id_list = None
        bind_to_ingress_lag_id_list = None
        bind_to_egress_lag_id_list = None
        bind_to_ingress_vlan_id_list = None
        bind_to_egress_vlan_id_list = None
        bind_to_ingress_rif_id_list = None
        bind_to_egress_rif_id_list = None
        bind_to_ingress_switch_id_list = None
        bind_to_egress_switch_id_list = None

        acl_table_id = sai_thrift_create_acl_table(self.client, addr_family,
                                                   stage,
                                                   bind_point,
                                                   table_priority,
                                                   mac_src, mac_dst,
                                                   ip_src, ip_dst,
                                                   ip_proto,
                                                   in_ports, out_ports,
                                                   in_port, out_port)

        acl_entry_id = sai_thrift_create_acl_entry(self.client, acl_table_id,
                                                   addr_family,
                                                   entry_priority,
                                                   action,
                                                   mac_src, mac_src_mask,
                                                   mac_dst, mac_dst_mask,
                                                   ip_src, ip_src_mask,
                                                   ip_dst, ip_dst_mask,
                                                   ip_proto,
                                                   in_ports, out_ports,
                                                   in_port, out_port,
                                                   ingress_mirror_id,
                                                   egress_mirror_id)

        acl_bind_object_id = sai_thrift_acl_bind_to_object(self.client, acl_table_id,
                                                           bind_to_ingress_port_id_list,
                                                           bind_to_egress_port_id_list,
                                                           bind_to_ingress_lag_id_list,
                                                           bind_to_egress_lag_id_list,
                                                           bind_to_ingress_vlan_id_list,
                                                           bind_to_egress_vlan_id_list,
                                                           bind_to_ingress_rif_id_list,
                                                           bind_to_egress_rif_id_list,
                                                           bind_to_ingress_switch_id_list,
                                                           bind_to_egress_switch_id_list)

        try:
            # send the same packet
            send_packet(self, 2, str(pkt))
            # ensure packet is dropped
            # check for absence of packet here!
            verify_no_packet(self, exp_pkt, 1)
        finally:
            # delete ACL
            self.client.sai_thrift_acl_unbind_from_object(acl_bind_object_id)
            self.client.sai_thrift_delete_acl_entry(acl_entry_id)
            self.client.sai_thrift_delete_acl_table(acl_table_id)

            # cleanup
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, rif_id1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)
