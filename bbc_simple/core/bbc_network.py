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
import redis
import threading
import logging
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc_simple.core.user_message_routing import UserMessageRouting
from bbc_simple.core.data_handler import DataHandler
from bbc_simple.core import message_key_types
from bbc_simple.core import bbclib
from bbc_simple.core.message_key_types import to_2byte, PayloadType


MSG_EXPIRE_SECONDS = 30


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

    def __init__(self, config, core=None):
        self.core = core
        self.stats = core.stats
        self.logger = core.logger
        self.config = config
        self.domains = dict()
        self.redis_pubsub = None
        self.pubsub = None
        conf = self.config.get_config()['redis']
        if 'password' in conf:
            pool = redis.ConnectionPool(host=conf['host'], port=conf['port'], ssl=conf.get('ssl', False),
                                        password=conf['password'], db=0)
        else:
            pool = redis.ConnectionPool(host=conf['host'], port=conf['port'], ssl=conf.get('ssl', False), db=0)
        th = threading.Thread(target=self._redis_loop, args=(pool,))
        th.setDaemon(True)
        th.start()
        self.redis_msg = redis.StrictRedis(connection_pool=pool, db=1)

    def _redis_loop(self, pool):
        self.redis_pubsub = redis.StrictRedis(connection_pool=pool)
        pubsub = self.redis_pubsub.pubsub()
        pubsub.psubscribe(["*"])
        for msg in pubsub.listen():
            if msg['type'] == 'psubscribe':
                continue
            domain_id = msg['channel']
            if domain_id not in self.domains:
                continue
            self.domains[domain_id]['user'].put_message((msg['data'], 0))

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
        db_default = self.config.get_config()['db']
        self.domains[domain_id]['data'] = DataHandler(self, default_config=db_default, config=conf,
                                                      workingdir=workingdir, domain_id=domain_id)

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

        del self.domains[domain_id]
        self.config.remove_domain_config(domain_id)
        self.stats.update_stats_decrement("network", "num_domains", 1)
        self.logger.info("Domain %s is removed" % (domain_id.hex()))
        return True

    def send_message_in_network(self, domain_id, dst_user_id, msg):
        """Send message to another user

        Args:
            domain_id (bytes): target domain_id
            dst_user_id (bytes): target user_id
            msg (dict): message to send
        """
        dat = bytes(message_key_types.make_message(PayloadType.Type_msgpack, msg))
        dst_info = bytearray(int(0).to_bytes(1, 'big'))
        dst_info.extend(int(len(dst_user_id)).to_bytes(1, 'big'))
        dst_info.extend(int(len(domain_id)).to_bytes(1, 'big'))
        dst_info.extend(dst_user_id)
        dst_info.extend(domain_id)
        dst_info = bytes(dst_info)
        if not self.redis_msg.exists(dst_info):
            self.redis_msg.lpush(dst_info, dat)
            self.redis_msg.expire(dst_info, MSG_EXPIRE_SECONDS)
        else:
            self.redis_msg.lpush(dst_info, dat)
        self.redis_pubsub.publish(domain_id, dst_info)

    def broadcast_notification_message(self, domain_id, msg):
        """Send notification message to users

        Args:
            domain_id (bytes): target domain_id
            msg (bytes): message to broadcast
        """
        dst_info = bytearray(int(1).to_bytes(1, 'big'))
        dst_info.extend(msg)
        dst_info = bytes(dst_info)
        self.redis_pubsub.publish(domain_id, dst_info)
