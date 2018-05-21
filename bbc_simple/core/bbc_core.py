#!/bin/sh
""":" .

exec python "$0" "$@"
"""
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 quvox.net.

This code is based on that in bbc-1 (https://github.com/beyond-blockchain/bbc1.git)

"""
from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
from gevent.server import StreamServer
import socket as py_socket
from gevent.socket import wait_read
import gevent
import os
import signal
import hashlib
import binascii
import traceback
import json
import copy
from argparse import ArgumentParser

import sys
sys.path.extend(["../../"])
from bbc_simple.core import bbclib
from bbc_simple.core.message_key_types import KeyType, to_2byte, InfraMessageCategory
from bbc_simple.core.bbclib import BBcTransaction, MsgType
from bbc_simple.core import bbc_network, user_message_routing, data_handler, message_key_types
from bbc_simple.core import query_management, bbc_stats
from bbc_simple.core.bbc_config import BBcConfig
from bbc_simple.core.bbc_error import *
from bbc_simple.logger.fluent_logger import get_fluent_logger

from bbc_simple.core.bbc_config import DEFAULT_CORE_PORT


VERSION = "bbc_simple v0.1"

PID_FILE = "/tmp/bbc_simple.pid"
POOL_SIZE = 1000
DEFAULT_ANYCAST_TTL = 5
TX_TRAVERSAL_MAX = 30

ticker = query_management.get_ticker()
core_service = None


def _make_message_structure(domain_id, cmd, dstid, qid):
    """Create a base structure of message

    Args:
        domain_id (bytes): the target domain_id
        cmd (bytes): command type in message_key_types.KeyType
        dstid (bytes): destination user_id
        qid (bytes): query_id to include in the message
    Returns:
        dict: message
    """
    return {
        KeyType.domain_id: domain_id,
        KeyType.command: cmd,
        KeyType.destination_user_id: dstid,
        KeyType.query_id: qid,
        KeyType.status: ESUCCESS,
    }


def _create_search_result(txobj_dict):
    """Create transaction search result"""
    response_info = dict()
    for txid, txobj in txobj_dict.items():
        if txid != txobj.transaction_id:
            response_info.setdefault(KeyType.compromised_transactions, list()).append(txobj.transaction_data)
            continue
        if bbclib.validate_transaction_object(txobj):
            response_info.setdefault(KeyType.transactions, list()).append(txobj.transaction_data)
        else:
            response_info.setdefault(KeyType.compromised_transactions, list()).append(txobj.transaction_data)
    return response_info


class BBcCoreService:
    """Base service object of BBc-1"""
    def __init__(self, core_port=None, ipv6=False, workingdir=".bbc1", configfile=None, server_start=True):
        self.logger = get_fluent_logger(name="bbc_core")
        self.stats = bbc_stats.BBcStats()
        self.config = BBcConfig(workingdir, configfile)
        conf = self.config.get_config()
        self.ipv6 = ipv6
        self.logger.debug("config = %s" % conf)
        self.test_tx_obj = BBcTransaction()
        self.insert_notification_user_list = dict()
        self.networking = bbc_network.BBcNetwork(self.config, core=self)
        for domain_id_str in conf['domains'].keys():
            domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)
            c = self.config.get_domain_config(domain_id)
            self.networking.create_domain(domain_id=domain_id, config=c)

        gevent.signal(signal.SIGINT, self.quit_program)
        if server_start:
            self._start_server(core_port)

    def quit_program(self):
        """Processes when quiting program"""
        self.config.update_config()
        os._exit(0)

    def _start_server(self, port):
        """Start TCP(v4 or v6) server"""
        pool = Pool(POOL_SIZE)
        if self.ipv6:
            server = StreamServer(("::", port), self._handler, spawn=pool)
        else:
            server = StreamServer(("0.0.0.0", port), self._handler, spawn=pool)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

    def _error_reply(self, msg=None, err_code=EINVALID_COMMAND, txt=""):
        """Create and send error reply message

        Args:
            msg (dict): message to send
            err_code (int): error code defined in bbc_error.py
            txt (str): error message
        Returns:
            bool:
        """
        msg[KeyType.status] = err_code
        msg[KeyType.reason] = txt
        domain_id = msg[KeyType.domain_id]
        if domain_id in self.networking.domains:
            self.networking.domains[domain_id]['user'].send_message_to_user(msg)
            return True
        else:
            return False

    def _handler(self, socket, address):
        """Message wait loop for a client"""
        # self.logger.debug("New connection")
        self.stats.update_stats_increment("client", "total_num", 1)
        user_info = None
        msg_parser = message_key_types.Message()
        try:
            while True:
                wait_read(socket.fileno())
                buf = socket.recv(8192)
                if len(buf) == 0:
                    break
                msg_parser.recv(buf)
                while True:
                    msg = msg_parser.parse()
                    if msg is None:
                        break
                    disconnection, new_info = self._process(socket, msg, msg_parser.payload_type)
                    if disconnection:
                        break
                    if new_info is not None:
                        user_info = new_info
        except Exception as e:
            self.logger.info("TCP disconnect: %s" % e)
            traceback.print_exc()
        self.logger.debug("closing socket")
        if user_info is not None:
            self.networking.domains[user_info[0]]['user'].unregister_user(user_info[1], socket)
        try:
            socket.shutdown(py_socket.SHUT_RDWR)
            socket.close()
        except:
            pass
        self.logger.debug("connection closed")
        self.stats.update_stats_decrement("client", "total_num", 1)

    def _param_check(self, param, dat):
        """Check if the param is included

        Args:
            param (bytes|list): Commands that must be included in the message
            dat (dict): received message
        Returns:
            bool: True if check is successful
        """
        if isinstance(param, list):
            for p in param:
                if p not in dat:
                    self._error_reply(msg=dat, err_code=EINVALID_COMMAND, txt="lack of mandatory params")
                    return False
        else:
            if param not in dat:
                self._error_reply(msg=dat, err_code=EINVALID_COMMAND, txt="lack of mandatory params")
                return False
        return True

    def _process(self, socket, dat, payload_type):
        """Process received message

        Args:
            socket (Socket): server socket
            dat (dict): received message
            payload_type (bytes): PayloadType value of msg
        Returns:
            bool: True if disconnection is detected
            list: return user info (domain_id, user_id) when a new user_id is coming
        """
        self.stats.update_stats_increment("client", "num_message_receive", 1)
        #self.logger.debug("process message from %s: %s" % (binascii.b2a_hex(dat[KeyType.source_user_id]), dat))
        if not self._param_check([KeyType.command, KeyType.source_user_id], dat):
            self.logger.debug("message has bad format")
            return False, None

        domain_id = dat.get(KeyType.domain_id, None)
        umr = None
        if domain_id is not None:
            if domain_id in self.networking.domains:
                umr = self.networking.domains[domain_id]['user']
            else:
                umr = user_message_routing.UserMessageRoutingDummy(networking=self.networking, domain_id=domain_id)

        cmd = dat[KeyType.command]
        if cmd == MsgType.REQUEST_SEARCH_TRANSACTION:
            if not self._param_check([KeyType.domain_id, KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_SEARCH_TRANSACTION: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_SEARCH_TRANSACTION,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            txinfo = self._search_transaction_by_txid(domain_id, dat[KeyType.transaction_id])
            if txinfo is None:
                if not self._error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)
                return False, None
            if KeyType.compromised_transaction_data in txinfo:
                retmsg[KeyType.status] = EBADTRANSACTION
            retmsg.update(txinfo)
            umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_SEARCH_WITH_CONDITIONS:
            if not self._param_check([KeyType.domain_id], dat):
                self.logger.debug("REQUEST_SEARCH_WITH_CONDITIONS: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_SEARCH_WITH_CONDITIONS,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            txinfo = self.search_transaction_with_condition(domain_id,
                                                            asset_group_id=dat.get(KeyType.asset_group_id, None),
                                                            asset_id=dat.get(KeyType.asset_id, None),
                                                            user_id=dat.get(KeyType.user_id, None),
                                                            count=dat.get(KeyType.count, 1))
            if txinfo is None or KeyType.transactions not in txinfo:
                if not self._error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                retmsg.update(txinfo)
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_TRAVERSE_TRANSACTIONS:
            if not self._param_check([KeyType.domain_id, KeyType.transaction_id,
                                     KeyType.direction, KeyType.hop_count], dat):
                self.logger.debug("REQUEST_TRAVERSE_TRANSACTIONS: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_TRAVERSE_TRANSACTIONS,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.transaction_id] = dat[KeyType.transaction_id]
            all_included, txtree = self._traverse_transactions(domain_id, dat[KeyType.transaction_id],
                                                               dat[KeyType.direction], dat[KeyType.hop_count])
            if txtree is None or len(txtree) == 0:
                if not self._error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                retmsg[KeyType.transaction_tree] = txtree
                retmsg[KeyType.all_included] = all_included
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_GATHER_SIGNATURE:
            if not self._param_check([KeyType.domain_id, KeyType.transaction_data], dat):
                self.logger.debug("REQUEST_GATHER_SIGNATURE: bad format")
                return False, None
            if not self._distribute_transaction_to_gather_signatures(dat[KeyType.domain_id], dat):
                retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GATHER_SIGNATURE,
                                                dat[KeyType.source_user_id], dat[KeyType.query_id])
                if not self._error_reply(msg=retmsg, err_code=EINVALID_COMMAND, txt="Fail to forward transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_INSERT:
            if not self._param_check([KeyType.domain_id, KeyType.transaction_data], dat):
                self.logger.debug("REQUEST_INSERT: bad format")
                return False, None
            transaction_data = dat[KeyType.transaction_data]
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_INSERT,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            ret = self.insert_transaction(dat[KeyType.domain_id], transaction_data)
            if isinstance(ret, str):
                if not self._error_reply(msg=retmsg, err_code=EINVALID_COMMAND, txt=ret):
                    user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                retmsg.update(ret)
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.RESPONSE_SIGNATURE:
            if not self._param_check([KeyType.domain_id, KeyType.destination_user_id, KeyType.source_user_id], dat):
                self.logger.debug("RESPONSE_SIGNATURE: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GATHER_SIGNATURE,
                                             dat[KeyType.destination_user_id], dat[KeyType.query_id])
            if KeyType.signature in dat:
                retmsg[KeyType.transaction_data_format] = dat[KeyType.transaction_data_format]
                retmsg[KeyType.signature] = dat[KeyType.signature]
                retmsg[KeyType.ref_index] = dat[KeyType.ref_index]
            elif KeyType.status not in dat:
                retmsg[KeyType.status] = EOTHER
                retmsg[KeyType.reason] = dat[KeyType.reason]
            elif dat[KeyType.status] < ESUCCESS:
                retmsg[KeyType.status] = dat[KeyType.status]
                retmsg[KeyType.reason] = dat[KeyType.reason]
            retmsg[KeyType.source_user_id] = dat[KeyType.source_user_id]
            umr.send_message_to_user(retmsg)

        elif cmd == MsgType.MESSAGE:
            if not self._param_check([KeyType.domain_id, KeyType.source_user_id, KeyType.destination_user_id], dat):
                self.logger.debug("MESSAGE: bad format")
                return False, None
            if KeyType.is_anycast in dat:
                dat[KeyType.anycast_ttl] = DEFAULT_ANYCAST_TTL
            umr.send_message_to_user(dat)

        elif cmd == MsgType.REGISTER:
            if domain_id is None:
                return False, None
            if not self._param_check([KeyType.domain_id, KeyType.source_user_id], dat):
                self.logger.debug("REGISTER: bad format")
                return False, None
            user_id = dat[KeyType.source_user_id]
            self.logger.debug("[%s] register_user: %s" % (binascii.b2a_hex(domain_id[:2]),
                                                          binascii.b2a_hex(user_id[:4])))
            umr.register_user(user_id, socket, on_multiple_nodes=dat.get(KeyType.on_multinodes, False))
            return False, (domain_id, user_id)

        elif cmd == MsgType.UNREGISTER:
            if umr is not None:
                umr.unregister_user(dat[KeyType.source_user_id], socket)
            return True, None

        elif cmd == MsgType.REQUEST_INSERT_NOTIFICATION:
            self._register_to_notification_list(domain_id, dat[KeyType.asset_group_id], dat[KeyType.source_user_id])

        elif cmd == MsgType.CANCEL_INSERT_NOTIFICATION:
            self.remove_from_notification_list(domain_id, dat[KeyType.asset_group_id], dat[KeyType.source_user_id])

        elif cmd == MsgType.REQUEST_GET_STATS:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_STATS,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.stats] = copy.deepcopy(self.stats.get_stats())
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_CONFIG:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_CONFIG,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            jsondat = self.config.get_json_config()
            retmsg[KeyType.bbc_configuration] = jsondat
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_DOMAINLIST:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_DOMAINLIST,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(self.networking.domains)))
            for domain_id in self.networking.domains:
                data.extend(domain_id)
            retmsg[KeyType.domain_list] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_FORWARDING_LIST:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_FORWARDING_LIST,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(umr.forwarding_entries)))
            for user_id in umr.forwarding_entries:
                data.extend(user_id)
                data.extend(to_2byte(len(umr.forwarding_entries[user_id]['nodes'])))
                for node_id in umr.forwarding_entries[user_id]['nodes']:
                    data.extend(node_id)
            retmsg[KeyType.forwarding_list] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_USERS:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_USERS,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(umr.registered_users)))
            for user_id in umr.registered_users.keys():
                data.extend(user_id)
            retmsg[KeyType.user_list] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_NODEID:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_NODEID,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(self.networking.domains[domain_id]['topology'].my_node_id)
            retmsg[KeyType.node_id] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_NOTIFICATION_LIST:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_NOTIFICATION_LIST,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(self.insert_notification_user_list[domain_id])))
            for asset_group_id in self.insert_notification_user_list[domain_id].keys():
                data.extend(asset_group_id)
                data.extend(to_2byte(len(self.insert_notification_user_list[domain_id][asset_group_id])))
                for user_id in self.insert_notification_user_list[domain_id][asset_group_id]:
                    data.extend(user_id)
            retmsg[KeyType.notification_list] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_SETUP_DOMAIN:
            if not self._param_check([KeyType.domain_id], dat):
                self.logger.debug("REQUEST_SETUP_DOMAIN: bad format")
                return False, None
            retmsg = _make_message_structure(None, MsgType.RESPONSE_SETUP_DOMAIN,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.result] = self.networking.create_domain(domain_id=domain_id)
            if not retmsg[KeyType.result]:
                retmsg[KeyType.reason] = "Already exists"
            retmsg[KeyType.domain_id] = domain_id
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_CLOSE_DOMAIN:
            retmsg = _make_message_structure(None, MsgType.RESPONSE_CLOSE_DOMAIN,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.result] = self.networking.remove_domain(domain_id)
            if not retmsg[KeyType.result]:
                retmsg[KeyType.reason] = "No such domain"
            user_message_routing.direct_send_to_user(socket, retmsg)

        else:
            self.logger.error("Bad command/response: %s" % cmd)
        return False, None

    def _register_to_notification_list(self, domain_id, asset_group_id, user_id):
        """Register user_id in insert completion notification list

        Args:
            domain_id (bytes): target domain_id
            asset_group_id (bytes): target asset_group_id of which you want to get notification about the insertion
            user_id (bytes): user_id that registers in the list
        """
        self.insert_notification_user_list.setdefault(domain_id, dict())
        self.insert_notification_user_list[domain_id].setdefault(asset_group_id, set())
        self.insert_notification_user_list[domain_id][asset_group_id].add(user_id)
        umr = self.networking.domains[domain_id]['user']
        umr.send_multicast_join(asset_group_id, permanent=True)

    def remove_from_notification_list(self, domain_id, asset_group_id, user_id):
        """Remove entry from insert completion notification list

        This method checks validation only.

        Args:
            domain_id (bytes): target domain_id
            asset_group_id (bytes): target asset_group_id of which you want to get notification about the insertion
            user_id (bytes): user_id that registers in the list
        """
        if domain_id not in self.insert_notification_user_list:
            return
        if asset_group_id is not None:
            if asset_group_id in self.insert_notification_user_list[domain_id]:
                self._remove_notification_entry(domain_id, asset_group_id, user_id)
        else:
            for asset_group_id in list(self.insert_notification_user_list[domain_id]):
                self._remove_notification_entry(domain_id, asset_group_id, user_id)

    def _remove_notification_entry(self, domain_id, asset_group_id, user_id):
        """Remove entry from insert completion notification list

        Args:
            domain_id (bytes): target domain_id
            asset_group_id (bytes): target asset_group_id of which you want to get notification about the insertion
            user_id (bytes): user_id that registers in the list
        """
        self.insert_notification_user_list[domain_id][asset_group_id].remove(user_id)
        if len(self.insert_notification_user_list[domain_id][asset_group_id]) == 0:
            self.insert_notification_user_list[domain_id].pop(asset_group_id, None)
            umr = self.networking.domains[domain_id]['user']
            umr.send_multicast_leave(asset_group_id)
        if len(self.insert_notification_user_list[domain_id]) == 0:
            self.insert_notification_user_list.pop(domain_id, None)

    def validate_transaction(self, txdata):
        """Validate transaction by verifying signature

        Args:
            txdata (bytes): serialized transaction data
        Returns:
            BBcTransaction: if validation fails, None returns.
        """
        txobj = BBcTransaction()
        if not txobj.deserialize(txdata):
            self.stats.update_stats_increment("transaction", "invalid", 1)
            self.logger.error("Fail to deserialize transaction data")
            return None
        txobj.digest()

        if bbclib.validate_transaction_object(txobj):
            return txobj
        else:
            self.stats.update_stats_increment("transaction", "invalid", 1)
            return None

    def insert_transaction(self, domain_id, txdata):
        """Insert transaction into ledger

        Args:
            domain_id (bytes): target domain_id
            txdata (bytes): serialized transaction data
        Returns:
            dict|str: inserted transaction_id or error message
        """
        self.stats.update_stats_increment("transaction", "insert_count", 1)
        if domain_id is None:
            self.stats.update_stats_increment("transaction", "insert_fail_count", 1)
            self.logger.error("No such domain")
            return "Set up the domain, first!"
        txobj = self.validate_transaction(txdata)
        if txobj is None:
            self.stats.update_stats_increment("transaction", "insert_fail_count", 1)
            self.logger.error("Bad transaction format")
            return "Bad transaction format"
        self.logger.debug("[node:%s] insert_transaction %s" %
                          (self.networking.domains[domain_id]['name'], binascii.b2a_hex(txobj.transaction_id[:4])))

        asset_group_ids = self.networking.domains[domain_id]['data'].insert_transaction(txdata, txobj=txobj)
        if asset_group_ids is None:
            self.stats.update_stats_increment("transaction", "insert_fail_count", 1)
            self.logger.error("[%s] Fail to insert a transaction into the ledger" % self.networking.domains[domain_id]['name'])
            return "Failed to insert a transaction into the ledger"

        self.send_inserted_notification(domain_id, asset_group_ids, txobj.transaction_id)

        return {KeyType.transaction_id: txobj.transaction_id}

    def send_inserted_notification(self, domain_id, asset_group_ids, transaction_id, only_registered_user=False):
        """Broadcast NOTIFY_INSERTED

        Args:
            domain_id (bytes): target domain_id
            asset_group_ids (list): list of asset_group_ids
            transaction_id (bytes): transaction_id that has just inserted
            only_registered_user (bool): If True, notification is not sent to other nodes
        """
        umr = self.networking.domains[domain_id]['user']
        destination_users = set()
        destination_nodes = set()
        for asset_group_id in asset_group_ids:
            if domain_id in self.insert_notification_user_list:
                if asset_group_id in self.insert_notification_user_list[domain_id]:
                    for user_id in self.insert_notification_user_list[domain_id][asset_group_id]:
                        destination_users.add(user_id)
            if not only_registered_user:
                if asset_group_id in umr.forwarding_entries:
                    for node_id in umr.forwarding_entries[asset_group_id]['nodes']:
                        destination_nodes.add(node_id)

        if len(destination_users) == 0 and len(destination_nodes) == 0:
            return
        msg = {
            KeyType.domain_id: domain_id,
            KeyType.infra_command: data_handler.DataHandler.NOTIFY_INSERTED,
            KeyType.command: MsgType.NOTIFY_INSERTED,
            KeyType.transaction_id: transaction_id,
        }
        for user_id in destination_users:
            msg[KeyType.destination_user_id] = user_id
            if not umr.send_message_to_user(msg=msg, direct_only=True):
                self.remove_from_notification_list(domain_id, None, user_id)

        msg[KeyType.infra_msg_type] = InfraMessageCategory.CATEGORY_DATA
        for node_id in destination_nodes:   # TODO: need test (multiple asset_groups are bundled)
            msg[KeyType.destination_node_id] = node_id
            self.networking.send_message_in_network(domain_id=domain_id, msg=msg)

    def _distribute_transaction_to_gather_signatures(self, domain_id, dat):
        """Request to distribute sign_request to users

        Args:
            domain_id (bytes): target domain_id
            dat (dict): message to send
        Returns:
            bool: True
        """
        destinations = dat[KeyType.destination_user_ids]
        msg = _make_message_structure(domain_id, MsgType.REQUEST_SIGNATURE, None, dat[KeyType.query_id])
        msg[KeyType.source_user_id] = dat[KeyType.source_user_id]
        umr = self.networking.domains[domain_id]['user']
        for dst in destinations:
            if dst == dat[KeyType.source_user_id]:
                continue
            msg[KeyType.destination_user_id] = dst
            if KeyType.hint in dat:
                msg[KeyType.hint] = dat[KeyType.hint]
            msg[KeyType.transaction_data] = dat[KeyType.transaction_data]
            if KeyType.transactions in dat:
                msg[KeyType.transactions] = dat[KeyType.transactions]
            umr.send_message_to_user(msg)
        return True

    def _search_transaction_by_txid(self, domain_id, transaction_id):
        """Search transaction_data by transaction_id

        Args:
            domain_id (bytes): target domain_id
            transaction_id (bytes): transaction_id to search
        Returns:
            dict: dictionary having transaction_id, serialized transaction data, asset files
        """
        self.stats.update_stats_increment("transaction", "search_count", 1)
        if domain_id is None:
            self.logger.error("No such domain")
            return None
        if transaction_id is None:
            self.logger.error("Transaction_id must not be None")
            return None

        dh = self.networking.domains[domain_id]['data']
        ret_txobj = dh.search_transaction(transaction_id=transaction_id)
        if ret_txobj is None or len(ret_txobj) == 0:
            return None

        response_info = _create_search_result(ret_txobj)
        response_info[KeyType.transaction_id] = transaction_id
        if KeyType.transactions in response_info:
            response_info[KeyType.transaction_data] = response_info[KeyType.transactions][0]
            del response_info[KeyType.transactions]
        elif KeyType.compromised_transactions in response_info:
            response_info[KeyType.compromised_transaction_data] = response_info[KeyType.compromised_transactions][0]
            del response_info[KeyType.compromised_transactions]
        return response_info

    def search_transaction_with_condition(self, domain_id, asset_group_id=None, asset_id=None, user_id=None, count=1):
        """Search transactions that match given conditions

        When Multiple conditions are given, they are considered as AND condition.

        Args:
            domain_id (bytes): target domain_id
            asset_group_id (bytes): asset_group_id that target transactions should have
            asset_id (bytes): asset_id that target transactions should have
            user_id (bytes): user_id that target transactions should have
            count (int): The maximum number of transactions to retrieve
        Returns:
            dict: dictionary having transaction_id, serialized transaction data, asset files
        """
        if domain_id is None:
            self.logger.error("No such domain")
            return None

        dh = self.networking.domains[domain_id]['data']
        ret_txobj = dh.search_transaction(asset_group_id=asset_group_id, asset_id=asset_id, user_id=user_id, count=count)
        if ret_txobj is None or len(ret_txobj) == 0:
            return None

        return _create_search_result(ret_txobj)

    def _traverse_transactions(self, domain_id, transaction_id, direction=1, hop_count=3):
        """Get transaction tree from the specified transaction_id

        Transaction tree in the return values are in the following format:
        [ [list of serialized transactions in 1-hop from the base], [list of serialized transactions in 2-hop from the base],,,,

        Args:
            domain_id (bytes): target domain_id
            transaction_id (bytes): the base transaction_id from which traverse starts
            direction (int): 1:backward, non-1:forward
            hop_count (bytes): hop count to traverse
        Returns:
            list: list of [include_all_flag, transaction tree]
        """
        self.stats.update_stats_increment("transaction", "search_count", 1)
        if domain_id is None:
            self.logger.error("No such domain")
            return None
        if transaction_id is None:
            self.logger.error("Transaction_id must not be None")
            return None

        dh = self.networking.domains[domain_id]['data']
        txtree = list()

        traverse_to_past = True if direction == 1 else False
        tx_count = 0
        txids = dict()
        current_txids = [transaction_id]
        include_all_flag = True
        if hop_count > TX_TRAVERSAL_MAX * 2:
            hop_count = TX_TRAVERSAL_MAX * 2
            include_all_flag = False
        for i in range(hop_count):
            tx_brothers = list()
            next_txids = list()
            #print("### txcount=%d, len(current_txids)=%d" % (tx_count, len(current_txids)))
            if tx_count + len(current_txids) > TX_TRAVERSAL_MAX:  # up to 30 entries
                include_all_flag = False
                break
            #print("[%d] current_txids:%s" % (i, [d.hex() for d in current_txids]))
            for txid in current_txids:
                if txid in txids:
                    continue
                tx_count += 1
                txids[txid] = True
                ret_txobj = dh.search_transaction(transaction_id=txid)
                if ret_txobj is None or len(ret_txobj) == 0:
                    continue
                tx_brothers.append(ret_txobj[txid].transaction_data)

                ret = dh.search_transaction_topology(transaction_id=txid, traverse_to_past=traverse_to_past)
                #print("txid=%s: (%d) ret=%s" % (txid.hex(), len(ret), ret))
                if ret is not None:
                    for topology in ret:
                        if traverse_to_past:
                            next_txid = topology[2]
                        else:
                            next_txid = topology[1]
                        if next_txid not in txids:
                            next_txids.append(next_txid)
            if len(tx_brothers) > 0:
                txtree.append(tx_brothers)
            current_txids = next_txids

        return include_all_flag, txtree


def daemonize(pidfile=PID_FILE):
    """Run in background"""
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        f2 = open(pidfile, 'w')
        f2.write(str(pid)+"\n")
        f2.close()
        os._exit(0)
    os.umask(0)


def parser():
    usage = 'python {} [--coreport <number>] [--workingdir <dir>] [--config <filename>] ' \
            '[-6] [--daemon] [--kill] [--help]'.format(__file__)
    argparser = ArgumentParser(usage=usage)
    argparser.add_argument('-cp', '--coreport', type=int, default=DEFAULT_CORE_PORT, help='waiting TCP port')
    argparser.add_argument('-w', '--workingdir', type=str, default=".bbc1", help='working directory name')
    argparser.add_argument('-c', '--config', type=str, default=None, help='config file name')
    argparser.add_argument('-6', '--ivp6', action='store_true', default=False, help='Use IPv6 for waiting TCP connection')
    argparser.add_argument('-d', '--daemon', action='store_true', help='run in background')
    argparser.add_argument('-k', '--kill', action='store_true', help='kill the daemon')
    args = argparser.parse_args()
    return args


if __name__ == '__main__':
    argresult = parser()
    if argresult.kill:
        import subprocess
        import sys
        subprocess.call("kill `cat " + PID_FILE + "`", shell=True)
        subprocess.call("rm -f " + PID_FILE, shell=True)
        sys.exit(0)
    if argresult.daemon:
        daemonize()
    BBcCoreService(
        core_port=argresult.coreport,
        workingdir=argresult.workingdir,
        configfile=argresult.config,
        ipv6=argresult.ipv6
    )
