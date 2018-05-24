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

import threading
import queue
import msgpack
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc_simple.core.message_key_types import PayloadType, KeyType
from bbc_simple.core import message_key_types
from bbc_simple.logger.fluent_logger import get_fluent_logger


def direct_send_to_user(sock, msg):
    sock.sendall(message_key_types.make_message(PayloadType.Type_msgpack, msg))


class UserMessageRouting:
    """Handle message for clients"""
    def __init__(self, networking, domain_id):
        self.networking = networking
        self.stats = networking.core.stats
        self.domain_id = domain_id
        self.logger = get_fluent_logger(name="user_message_routing")
        self.registered_users = dict()
        self.queue = queue.Queue()
        th = threading.Thread(target=self._message_loop)
        th.setDaemon(True)
        th.start()

    def register_user(self, user_id, socket, on_multiple_nodes=False):
        """Register user to forward message

        Args:
            user_id (bytes): user_id of the client
            socket (Socket): socket for the client
            on_multiple_nodes (bool): If True, the user_id is also registered in other nodes, meaning multicasting.
        """
        self.registered_users.setdefault(user_id, set())
        self.registered_users[user_id].add(socket)

    def unregister_user(self, user_id, socket):
        """Unregister user from the list and delete AES key if exists

        Args:
            user_id (bytes): user_id of the client
            socket (Socket): socket for the client
        """
        if user_id not in self.registered_users:
            return
        self.registered_users[user_id].remove(socket)
        if len(self.registered_users[user_id]) == 0:
            self.registered_users.pop(user_id, None)

    def send_message_to_user(self, msg, direct_only=False):
        """Forward message to connecting user

        Args:
            msg (dict): message to send
            direct_only (bool): If True, _forward_message_to_another_node is not called.
        """
        socks = self.registered_users.get(msg[KeyType.destination_user_id], None)
        if socks is None:
            if direct_only:
                return False
            self.networking.send_message_in_network(domain_id=self.domain_id,
                                                    dst_user_id=msg[KeyType.destination_user_id], msg=msg)
            return True
        return self._send(socks, msg)

    def _send(self, socks, msg, no_make=False):
        """Raw function to send a message"""
        count = len(socks)
        for s in socks:
            try:
                if no_make:
                    s.sendall(msg)
                else:
                    s.sendall(message_key_types.make_message(PayloadType.Type_msgpack, msg))
                self.stats.update_stats_increment("user_message", "sent_msg_to_user", 1)
            except:
                count -= 1
        return count > 0

    def put_message(self, msg=None):
        """append a message to the queue"""
        self.queue.put(msg)

    def _message_loop(self):
        """message loop for users"""
        while True:
            dst_user_id, idx = self.queue.get()
            if dst_user_id is None:
                continue
            socks = self.registered_users.get(dst_user_id, None)
            if socks is None:
                continue
            cnt = 3
            while cnt > 0 and self.networking.redis_msg.llen(dst_user_id) > idx:
                dat = self.networking.redis_msg.lindex(dst_user_id, idx)
                if dat is None and idx == 0:
                    self.networking.redis_msg.lpop(dst_user_id)
                    continue
                msg = msgpack.unpackb(dat[8:])
                if msg[KeyType.domain_id] == self.domain_id:
                    self.stats.update_stats_increment("user_message", "send_to_user", 1)
                    if self._send(socks, dat, no_make=True):
                        if idx == 0:
                            self.networking.redis_msg.lpop(dst_user_id)
                        else:
                            self.networking.redis_msg.lset(dst_user_id, idx, None)
                    else:
                        idx += 1
                    cnt -= 1
                else:
                    idx += 1
                if self.networking.redis_msg.llen(dst_user_id) == 0:
                    break
            if self.networking.redis_msg.llen(dst_user_id) > idx:
                self.queue.put((dst_user_id, idx))


class UserMessageRoutingDummy(UserMessageRouting):
    """Dummy class for bbc_core.py"""
    def register_user(self, user_id, socket, on_multiple_nodes=False):
        pass

    def unregister_user(self, user_id, socket=None):
        pass

    def put_message(self, msg=None):
        pass

    def send_message_to_user(self, msg, direct_only=False):
        pass
