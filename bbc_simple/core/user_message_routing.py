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
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc_simple.core.message_key_types import PayloadType, KeyType
from bbc_simple.core import message_key_types, bbc_network, bbclib
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
        self.insert_notification_list = dict()
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

    def register_notification(self, asset_group_id, user_id):
        """Register user to insert notification list

        Args:
            asset_group_id (bytes): asset_group_id to watch
            user_id (bytes): user_id of the notified client
        """
        self.insert_notification_list.setdefault(asset_group_id, set())
        self.insert_notification_list[asset_group_id].add(user_id)

    def unregister_notification(self, asset_group_id, user_id):
        """Unregister user from insert notification list

        Args:
            asset_group_id (bytes): watching asset_group_id
            user_id (bytes): user_id of the notified client
        """
        if asset_group_id not in self.insert_notification_list:
            return
        self.insert_notification_list[asset_group_id].remove(user_id)
        if len(self.insert_notification_list[asset_group_id]) == 0:
            del self.insert_notification_list[asset_group_id]

    def put_message(self, msg=None):
        """append a message to the queue"""
        self.queue.put(msg)

    def get_stored_messages(self, src_user_id, query_id):
        """send back all stored messages

        Args:
            src_user_id (bytes): user_id of requesting user
            query_id (bytes): query_id (synchronous response) or None (asynchronous response)
        """
        socks = self.registered_users.get(src_user_id, None)
        if socks is None:
            return
        dst_info = bytearray(int(0).to_bytes(1, 'big'))
        dst_info.extend(int(len(src_user_id)).to_bytes(1, 'big'))
        dst_info.extend(int(len(self.domain_id)).to_bytes(1, 'big'))
        dst_info.extend(src_user_id)
        dst_info.extend(self.domain_id)
        dst_info = bytes(dst_info)
        if query_id is None:
            while self.networking.redis_msg.llen(dst_info) > 0:
                dat = self.networking.redis_msg.lpop(dst_info)
                self._send(socks, dat, no_make=True)
        else:
            messages = list()
            while self.networking.redis_msg.llen(dst_info) > 0:
                dat = self.networking.redis_msg.lpop(dst_info)
                messages.append(dat)
            msg = {
                KeyType.domain_id: self.domain_id,
                KeyType.destination_user_id: src_user_id,
                KeyType.command: bbclib.MsgType.RESPONSE_GET_STORED_MESSAGES,
                KeyType.bulk_messages: messages,
            }
            self._send(socks, msg)

    def send_message_to_user(self, msg):
        """Forward message to connecting user

        Args:
            msg (dict): message to send
        """
        socks = self.registered_users.get(msg[KeyType.destination_user_id], None)
        if socks is None:
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

    def _message_loop(self):
        """message loop for users"""
        while True:
            dst_info, idx = self.queue.get()
            if dst_info is None:
                continue
            if dst_info[0] == 0:
                dst_user_id = dst_info[3:3+int(dst_info[1])]
                domain_id = dst_info[3+int(dst_info[1]):3+int(dst_info[1])+int(dst_info[2])]
                if domain_id != self.domain_id:
                    continue
                socks = self.registered_users.get(dst_user_id, None)
                if socks is None:
                    continue
                self._process_msg_queue(socks, dst_info)
            elif dst_info[0] == 1:
                transaction_id = dst_info[3:3+int(dst_info[1])]
                domain_id = dst_info[3+int(dst_info[1]):3+int(dst_info[1])+int(dst_info[2])]
                dat = dst_info[3+int(dst_info[1])+int(dst_info[2]):]
                if domain_id != self.domain_id:
                    continue
                self._send_notification(transaction_id, dat)

    def _process_msg_queue(self, socks, dst_info):
        cnt = 3
        while cnt > 0 and self.networking.redis_msg.llen(dst_info) > 0:
            dat = self.networking.redis_msg.lpop(dst_info)
            self.stats.update_stats_increment("user_message", "send_to_user", 1)
            self._send(socks, dat, no_make=True)
            self.networking.redis_msg.expire(dst_info, bbc_network.MSG_EXPIRE_SECONDS)
            cnt -= 1

    def _send_notification(self, transaction_id, dat):
        id_num = dat[0]
        id_len = int((len(dat)-1)/id_num)
        asset_group_ids = list()
        for i in range(id_num):
            asset_group_ids.append(dat[1+i*id_len:1+(i+1)*id_len])
        user_list = set()
        for asset_group_id in asset_group_ids:
            if asset_group_id in self.insert_notification_list:
                user_list = user_list.union(self.insert_notification_list[asset_group_id])
        if len(user_list) == 0:
            return
        msg = {
            KeyType.domain_id: self.domain_id,
            KeyType.command: bbclib.MsgType.NOTIFY_INSERTED,
            KeyType.transaction_id: transaction_id,
            KeyType.asset_group_ids: list(asset_group_ids),
        }
        for user_id in user_list:
            socks = self.registered_users.get(user_id, None)
            msg[KeyType.destination_user_id] = user_id
            if socks is None:
                continue
            self._send(socks, msg)


class UserMessageRoutingDummy(UserMessageRouting):
    """Dummy class for bbc_core.py"""
    def register_user(self, user_id, socket, on_multiple_nodes=False):
        pass

    def unregister_user(self, user_id, socket=None):
        pass

    def put_message(self, msg=None):
        pass

    def get_stored_messages(self, src_user_id, query_id):
        pass

    def send_message_to_user(self, msg):
        pass
