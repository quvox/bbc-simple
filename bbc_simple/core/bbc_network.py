# -*- coding: utf-8 -*-
"""
Copyright (c) 2017 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc_simple.core.user_message_routing import UserMessageRouting
from bbc_simple.core.data_handler import DataHandler
from bbc_simple.core import query_management, message_key_types
from bbc_simple.core import bbclib
from bbc_simple.core.message_key_types import to_2byte, PayloadType, KeyType, InfraMessageCategory
from bbc_simple.core.bbc_error import *
from bbc_simple.logger.fluent_logger import get_fluent_logger


ticker = query_management.get_ticker()


def _convert_to_string(array):
    """Data convert utility"""
    for i in range(len(array)):
        if isinstance(array[i], bytes):
            array[i] = array[i].decode()
    return array


def is_less_than(val_a, val_b):
    """Return True if val_a is less than val_b (evaluate as integer)"""
    size = len(val_a)
    if size != len(val_b):
        return False
    for i in reversed(range(size)):
        if val_a[i] < val_b[i]:
            return True
        elif val_a[i] > val_b[i]:
            return False
    return False


class BBcNetwork:
    """Socket and thread management for infrastructure layers"""
    NOTIFY_LEAVE = to_2byte(0)

    def __init__(self, config, core=None):
        self.core = core
        self.stats = core.stats
        self.logger = get_fluent_logger(name="bbc_network")
        self.config = config
        self.domains = dict()

    def create_domain(self, domain_id, config=None):
        """Create domain and register user in the domain

        Args:
            domain_id (bytes): target domain_id to create
            config (dict): configuration for the domain
        Returns:
            bool:
        """
        if domain_id in self.domains:
            return False

        conf = self.config.get_domain_config(domain_id, create_if_new=True)
        if config is not None:
            conf.update(config)
        if 'node_id' not in conf or conf['node_id'] == "":
            node_id = bbclib.get_random_id()
            conf['node_id'] = bbclib.convert_id_to_string(node_id)
            self.config.update_config()
        else:
            node_id = bbclib.convert_idstring_to_bytes(conf.get('node_id'))

        self.domains[domain_id] = dict()
        self.domains[domain_id]['node_id'] = node_id
        self.domains[domain_id]['name'] = node_id.hex()[:4]
        self.domains[domain_id]['user'] = UserMessageRouting(self, domain_id)

        workingdir = self.config.get_config()['workingdir']
        self.domains[domain_id]['data'] = DataHandler(self, config=conf, workingdir=workingdir, domain_id=domain_id)

        self.stats.update_stats_increment("network", "num_domains", 1)
        self.logger.info("Domain %s is created" % (domain_id.hex()))
        return True

    def remove_domain(self, domain_id):
        """Leave the domain and remove it

        Args:
            domain_id (bytes): target domain_id to remove
        Returns:
            bool: True if successful
        """
        if domain_id not in self.domains:
            return False
        self.domains[domain_id]['user'].stop_all_timers()

        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_NETWORK,
            KeyType.domain_id: domain_id,
            KeyType.command: BBcNetwork.NOTIFY_LEAVE,
            KeyType.source_node_id: self.domains[domain_id]["neighbor"].my_node_id,
            KeyType.nonce: bbclib.get_random_value(32)   # just for randomization
        }
        self.broadcast_message_in_network(domain_id=domain_id, msg=msg)

        del self.domains[domain_id]
        self.config.remove_domain_config(domain_id)
        self.stats.update_stats_decrement("network", "num_domains", 1)
        self.logger.info("Domain %s is removed" % (domain_id.hex()))
        return True

    def send_message_in_network(self, nodeinfo=None, payload_type=PayloadType.Type_any, domain_id=None, msg=None):
        """Send message over a domain network

        Args:
            nodeinfo (NodeInfo): NodeInfo object of the destination
            payload_type (bytes): message format type
            domain_id (bytes): target domain_id
            msg (dict): message to send
        Returns:
            bool: True if successful
        """
        if nodeinfo is None:
            if domain_id not in self.domains:
                return False
            if msg[KeyType.destination_node_id] not in self.domains[domain_id]['neighbor'].nodeinfo_list:
                return False
            nodeinfo = self.domains[domain_id]['neighbor'].nodeinfo_list[msg[KeyType.destination_node_id]]
        msg[KeyType.source_node_id] = self.domains[domain_id]['neighbor'].my_node_id

        if payload_type == PayloadType.Type_any:
            if nodeinfo.key_manager is not None and nodeinfo.key_manager.key_name is not None and \
                    nodeinfo.key_manager.key_name in message_key_types.encryptors:
                payload_type = PayloadType.Type_encrypted_msgpack
            else:
                payload_type = PayloadType.Type_msgpack

        if payload_type in [PayloadType.Type_msgpack, PayloadType.Type_binary]:
            data_to_send = message_key_types.make_message(payload_type, msg)
        elif payload_type == PayloadType.Type_encrypted_msgpack:
            payload_type = PayloadType.Type_encrypted_msgpack
            data_to_send = message_key_types.make_message(payload_type, msg, key_name=nodeinfo.key_manager.key_name)
            if data_to_send is None:
                self.logger.error("Fail to encrypt message")
                return False
        else:
            return False

        if len(data_to_send) > TCP_THRESHOLD_SIZE:
            _send_data_by_tcp(ipv4=nodeinfo.ipv4, ipv6=nodeinfo.ipv6, port=nodeinfo.port, msg=data_to_send)
            self.stats.update_stats_increment("network", "send_msg_by_tcp", 1)
            self.stats.update_stats_increment("network", "sent_data_size", len(data_to_send))
            return True
        if nodeinfo.ipv6 is not None and self.socket_udp6 is not None:
            self.socket_udp6.sendto(data_to_send, (nodeinfo.ipv6, nodeinfo.port))
            self.stats.update_stats_increment("network", "send_msg_by_udp6", 1)
            self.stats.update_stats_increment("network", "sent_data_size", len(data_to_send))
            return True
        if nodeinfo.ipv4 is not None and self.socket_udp is not None:
            self.socket_udp.sendto(data_to_send, (nodeinfo.ipv4, nodeinfo.port))
            self.stats.update_stats_increment("network", "send_msg_by_udp4", 1)
            self.stats.update_stats_increment("network", "sent_data_size", len(data_to_send))
            return True

    def broadcast_message_in_network(self, domain_id, payload_type=PayloadType.Type_any, msg=None):
        """Send message to all neighbor nodes

        Args:
            payload_type (bytes): message format type
            domain_id (bytes): target domain_id
            msg (dict): message to send
        Returns:
            bool: True if successful
        """
        if domain_id not in self.domains:
            return
        for node_id, nodeinfo in self.domains[domain_id]['neighbor'].nodeinfo_list.items():
            msg[KeyType.destination_node_id] = node_id
            #print("broadcast:", node_id.hex(), node_id)
            self.send_message_in_network(nodeinfo, payload_type, domain_id, msg)

    def _process_message_base(self, domain_id, ipv4, ipv6, port, msg):
        """Process received message (common process for any kind of network module)

        Args:
            domain_id (bytes): target domain_id
            ipv4 (str): IPv4 address of the sender node
            ipv6 (str): IPv6 address of the sender node
            port (int): Port number of the sender
            msg (dict): received message
        """
        if KeyType.infra_msg_type not in msg:
            return
        self.logger.debug("[%s] process_message(type=%d)" % (self.domains[domain_id]['name'],
                                                             int.from_bytes(msg[KeyType.infra_msg_type], 'big')))

        if msg[KeyType.infra_msg_type] == InfraMessageCategory.CATEGORY_NETWORK:
            self._process_message(domain_id, ipv4, ipv6, port, msg)

        elif msg[KeyType.infra_msg_type] == InfraMessageCategory.CATEGORY_USER:
            self.domains[domain_id]['user'].process_message(msg)
        elif msg[KeyType.infra_msg_type] == InfraMessageCategory.CATEGORY_DATA:
            self.domains[domain_id]['data'].process_message(msg)

    def _process_message(self, domain_id, ipv4, ipv6, port, msg):
        """Process received message

        Args:
            domain_id (bytes): target domain_id
            ipv4 (str): IPv4 address of the sender node
            ipv6 (str): IPv6 address of the sender node
            port (int): Port number of the sender
            msg (dict): received message
        """
        source_node_id = msg[KeyType.source_node_id]
        if source_node_id in self.domains[domain_id]["neighbor"].nodeinfo_list:
            admin_msg_seq = msg[KeyType.message_seq]
            if self.domains[domain_id]["neighbor"].nodeinfo_list[source_node_id].admin_sequence_number >= admin_msg_seq:
                return
            self.domains[domain_id]["neighbor"].nodeinfo_list[source_node_id].admin_sequence_number = admin_msg_seq

        elif msg[KeyType.command] == BBcNetwork.NOTIFY_LEAVE:
            if KeyType.source_node_id in msg:
                self.domains[domain_id]['topology'].notify_neighbor_update(source_node_id, is_new=False)
                self.domains[domain_id]['neighbor'].remove(source_node_id)
