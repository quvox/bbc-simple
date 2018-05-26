# -*- coding: utf-8 -*-
"""
Copyright (c) 2017 quvox.net

This code is based on that in bbc-1 (https://github.com/beyond-blockchain/bbc1.git)
"""
import gevent
from gevent import monkey
monkey.patch_all()
from gevent import socket
import traceback
import queue
import hashlib
import bson
import msgpack

import sys
sys.path.append("../../")

from bbc_simple.core import bbclib
from bbc_simple.core import message_key_types
from bbc_simple.core.bbclib import MsgType
from bbc_simple.core.message_key_types import KeyType, PayloadType
from bbc_simple.core.bbc_error import *
from bbc_simple.logger.fluent_logger import get_fluent_logger

DEFAULT_CORE_PORT = 9000

MESSAGE_WITH_NO_RESPONSE = (MsgType.MESSAGE, MsgType.REGISTER, MsgType.UNREGISTER, MsgType.DOMAIN_PING,
                            MsgType.REQUEST_INSERT_NOTIFICATION, MsgType.CANCEL_INSERT_NOTIFICATION,
                            MsgType.REQUEST_REPAIR)


def parse_one_level_list(dat):
    """Get list information from queued message
    Args:
        dat (bytes): received message data
    Returns:
        list: list of information
    """
    results = []
    count = int.from_bytes(dat[:2], 'big')
    for i in range(count):
        base = 2 + 32 * i
        results.append(dat[base:base + 32])
    return results


def parse_two_level_dict(dat):
    """Get hierarchical list information from queued message
    Args:
        dat (bytes): received message data
    Returns:
        dict: dictionary of information list
    """
    results = dict()
    count = int.from_bytes(dat[:2], 'big')
    ptr = 2
    for i in range(count):
        first_id = dat[ptr:ptr+32]
        ptr += 32
        results[first_id] = list()
        count2 = int.from_bytes(dat[ptr:ptr+2], 'big')
        ptr += 2
        for j in range(count2):
            second_id = dat[ptr:ptr+32]
            ptr += 32
            results[first_id].append(second_id)
    return results


class BBcAppClient:
    """Basic functions for a client of bbc_core"""
    def __init__(self, host='127.0.0.1', port=DEFAULT_CORE_PORT, multiq=True):
        self.logger = get_fluent_logger(name="bbc_app")
        self.connection = socket.create_connection((host, port))
        self.callback = Callback(log=self.logger)
        self.callback.set_client(self)
        self.use_query_id_based_message_wait = multiq
        self.user_id = None
        self.domain_id = None
        self.query_id = (0).to_bytes(2, 'little')
        self.start_receiver_loop()

    def set_callback(self, callback_obj):
        """Set callback object that implements message processing functions

        Args:
            callback_obj (obj): callback method object
        """
        self.callback = callback_obj
        self.callback.set_logger(self.logger)
        self.callback.set_client(self)

    def set_domain_id(self, domain_id):
        """Set domain_id to this client to include it in all messages

        Args:
            domain_id (bytes): domain_id to join in
        """
        self.domain_id = domain_id

    def set_user_id(self, identifier):
        """Set user_id of the object

        Args:
            identifier (bytes): user_id of this clients
        """
        self.user_id = identifier

    def include_admin_info(self, dat, admin_info, keypair):
        if keypair is not None:
            dat[KeyType.admin_info] = message_key_types.make_TLV_formatted_message(admin_info)
            digest = hashlib.sha256(dat[KeyType.admin_info]).digest()
            dat[KeyType.nodekey_signature] = keypair.sign(digest)
        else:
            dat.update(admin_info)

    def _make_message_structure(self, cmd):
        """Make a base message structure for sending to the core node

        Args:
            cmd (bytes): command type defined in bbclib.MsgType class
        """
        self.query_id = ((int.from_bytes(self.query_id, 'little') + 1) % 65536).to_bytes(2, 'little')
        if cmd not in MESSAGE_WITH_NO_RESPONSE:
            if self.use_query_id_based_message_wait:
                if self.query_id not in self.callback.query_queue:
                    self.callback.create_queue(self.query_id)
        msg = {
            KeyType.command: cmd,
            KeyType.domain_id: self.domain_id,
            KeyType.source_user_id: self.user_id,
            KeyType.query_id: self.query_id,
            KeyType.status: ESUCCESS,
        }
        return msg

    def _send_msg(self, dat):
        """Send the message to the core node

        Args:
            dat (dict): message object to send
        Returns:
            bytes: query ID for request/response type message
        """
        if KeyType.domain_id not in dat or KeyType.source_user_id not in dat:
            self.logger.warn("Message must include domain_id and source_id")
            return None
        try:
            msg = message_key_types.make_message(PayloadType.Type_msgpack, dat)
            self.connection.sendall(msg)
        except Exception as e:
            self.logger.error(traceback.format_exc())
            return None
        return self.query_id

    def domain_setup(self, domain_id, config=None):
        """Set up domain with the specified network module and storage

        This method should be used by a system administrator.

        Args:
            domain_id (bytes): domain_id to create
            config (str): system config in json format
        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_SETUP_DOMAIN)
        admin_info = {
            KeyType.domain_id: domain_id,
            KeyType.random: bbclib.get_random_value(32)
        }
        if config is not None:
            admin_info[KeyType.bbc_configuration] = config
        self.include_admin_info(dat, admin_info, None)
        return self._send_msg(dat)

    def domain_close(self, domain_id=None):
        """Close domain leading to remove_domain in the core

        Args:
            domain_id (bytes): domain_id to delete
        Returns:
            bytes: query_id
        """
        if domain_id is None and self.domain_id is not None:
            domain_id = self.domain_id
        if domain_id is None:
            return None
        dat = self._make_message_structure(MsgType.REQUEST_CLOSE_DOMAIN)
        admin_info = {
            KeyType.domain_id: domain_id,
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, None)
        return self._send_msg(dat)

    def get_node_id(self):
        """Get node_id of the connecting core node

        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_NODEID)
        return self._send_msg(dat)

    def get_bbc_config(self):
        """Get config file of bbc_core

        This method should be used by a system administrator.

        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_CONFIG)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, None)
        return self._send_msg(dat)

    def get_domain_list(self):
        """Get domain_id list in bbc_core

        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_DOMAINLIST)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, None)
        return self._send_msg(dat)

    def get_user_list(self):
        """Get user_ids in the domain that are connecting to the core node

        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_USERS)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, None)
        return self._send_msg(dat)

    def get_notification_list(self):
        """Get notification_list of the core node

        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_NOTIFICATION_LIST)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, None)
        return self._send_msg(dat)

    def register_to_core(self, on_multiple_nodes=False):
        """Register the client (user_id) to the core node

        After that, the client can communicate with the core node.

        Args:
            on_multiple_nodes (bool): True if this user_id is for multicast address
        Returns:
            bool: True
        """
        dat = self._make_message_structure(MsgType.REGISTER)
        if on_multiple_nodes:
            dat[KeyType.on_multinodes] = True
        self._send_msg(dat)
        return True

    def unregister_from_core(self):
        """Unregister and disconnect from the core node

        Returns:
            bool: True
        """
        dat = self._make_message_structure(MsgType.UNREGISTER)
        self._send_msg(dat)
        return True

    def request_insert_completion_notification(self, asset_group_id):
        """Request notification when a transaction has been inserted (as a copy of transaction)

        Args:
            asset_group_id (bytes): asset_group_id for requesting notification about insertion
        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_INSERT_NOTIFICATION)
        dat[KeyType.asset_group_id] = asset_group_id
        return self._send_msg(dat)

    def cancel_insert_completion_notification(self, asset_group_id):
        """Cancel notification when a transaction has been inserted (as a copy of transaction)

        Args:
            asset_group_id (bytes): asset_group_id for requesting notification about insertion
        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.CANCEL_INSERT_NOTIFICATION)
        dat[KeyType.asset_group_id] = asset_group_id
        return self._send_msg(dat)

    def gather_signatures(self, txobj, reference_obj=None, destinations=None, anycast=False):
        """Request to gather signatures from the specified user_ids

        Args:
            txobj (BBcTransaction):
            reference_obj (BBcReference): BBcReference object that includes the information about destinations
            destinations (list): list of destination user_ids
            anycast (bool): True if this message is for anycasting
        Returns:
            bytes: query_id
        """
        if reference_obj is None and destinations is None:
            return False
        dat = self._make_message_structure(MsgType.REQUEST_GATHER_SIGNATURE)
        dat[KeyType.transaction_data] = txobj.serialize()
        dat[KeyType.transaction_id] = txobj.transaction_id
        if anycast:
            dat[KeyType.is_anycast] = True
        if reference_obj is not None:
            dat[KeyType.destination_user_ids] = reference_obj.get_destinations()
            referred_transactions = dict()
            referred_transactions.update(reference_obj.get_referred_transaction())
            if len(referred_transactions) > 0:
                dat[KeyType.transactions] = referred_transactions
        elif destinations is not None:
            dat[KeyType.destination_user_ids] = destinations
        return self._send_msg(dat)

    def sendback_signature(self, dest_user_id=None, transaction_id=None, ref_index=-1, signature=None, query_id=None):
        """Send back the signed transaction to the source

        This method is called if the receiver (signer) approves the transaction.

        Args:
            dest_user_id (bytes): destination user_id to send back
            transaction_id (bytes):
            ref_index (int): (optional) which reference in transaction the signature is for
            signature (BBcSignature): Signature that expresses approval of the transaction with transaction_id
            query_id: The query_id that was in the received SIGN_REQUEST message
        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.RESPONSE_SIGNATURE)
        dat[KeyType.destination_user_id] = dest_user_id
        dat[KeyType.transaction_id] = transaction_id
        dat[KeyType.ref_index] = ref_index
        if signature.format_type in [bbclib.BBcFormat.FORMAT_BSON, bbclib.BBcFormat.FORMAT_BSON_COMPRESS_BZ2]:
            dat[KeyType.signature] = bson.dumps(signature.serialize())
            dat[KeyType.transaction_data_format] = bbclib.BBcFormat.FORMAT_BSON
        else:
            dat[KeyType.signature] = signature.serialize()
            dat[KeyType.transaction_data_format] = bbclib.BBcFormat.FORMAT_BINARY
        if query_id is not None:
            dat[KeyType.query_id] = query_id
        return self._send_msg(dat)

    def sendback_denial_of_sign(self, dest_user_id=None, transaction_id=None, reason_text=None, query_id=None):
        """Send back the denial of sign the transaction

        This method is called if the receiver (signer) denies the transaction.

        Args:
            dest_user_id (bytes): destination user_id to send back
            transaction_id (bytes):
            reason_text (str): message to the requester about why the node denies the transaction
            query_id: The query_id that was in the received SIGN_REQUEST message
        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.RESPONSE_SIGNATURE)
        dat[KeyType.destination_user_id] = dest_user_id
        dat[KeyType.transaction_id] = transaction_id
        dat[KeyType.status] = EOTHER
        dat[KeyType.reason] = reason_text
        if query_id is not None:
            dat[KeyType.query_id] = query_id
        return self._send_msg(dat)

    def insert_transaction(self, tx_obj):
        """Request to insert a legitimate transaction

        Args:
            tx_obj (BBcTransaction): Transaction object to insert
        Returns:
            bytes: query_id
        """
        if tx_obj.transaction_id is None:
            tx_obj.digest()
        dat = self._make_message_structure(MsgType.REQUEST_INSERT)
        dat[KeyType.transaction_data] = tx_obj.serialize()
        return self._send_msg(dat)

    def search_transaction_with_condition(self, asset_group_id=None, asset_id=None, user_id=None, count=1):
        """Search transaction data by asset_group_id/asset_id/user_id

        If multiple conditions are specified, they are considered as AND condition.

        Args:
            asset_group_id (bytes): asset_group_id in BBcEvent and BBcRelations
            asset_id (bytes): asset_id in BBcAsset
            user_id (bytes): user_id in BBcAsset that means the owner of the asset
            count (int): the number of transactions to retrieve
        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_SEARCH_WITH_CONDITIONS)
        if asset_group_id is not None:
            dat[KeyType.asset_group_id] = asset_group_id
        if asset_id is not None:
            dat[KeyType.asset_id] = asset_id
        if user_id is not None:
            dat[KeyType.user_id] = user_id
        dat[KeyType.count] = count
        return self._send_msg(dat)

    def search_transaction(self, transaction_id):
        """Search request for a transaction

        Args:
            transaction_id (bytes): the target transaction to retrieve
        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_SEARCH_TRANSACTION)
        dat[KeyType.transaction_id] = transaction_id
        return self._send_msg(dat)

    def traverse_transactions(self, transaction_id, direction=1, hop_count=3):
        """Search request for transactions

        The method traverses the transaction graph in the ledger.
        The response from the bbc_core includes the list of transactions.

        Args:
            transaction_id (bytes): the target transaction to retrieve
            direction (int): 1:backforward, non-1:forward
            hop_count (int): hop count to traverse from the specified origin point
        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_TRAVERSE_TRANSACTIONS)
        dat[KeyType.transaction_id] = transaction_id
        dat[KeyType.direction] = direction
        dat[KeyType.hop_count] = hop_count
        return self._send_msg(dat)

    def get_stats(self):
        """Get statistics of bbc_core

        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_STATS)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, None)
        return self._send_msg(dat)

    def get_stored_messages(self, user_id=None, async=False):
        """Get statistics of bbc_core

        Args:
            user_id (bytes): user_id of the client
            async (bool): True if asynchronous response is required
        Returns:
            bytes: query_id
        """
        if user_id is None:
            if self.user_id is not None:
                user_id = self.user_id
        if user_id is None:
            self.logger.error("user_id is not specified")
            return None
        dat = self._make_message_structure(MsgType.REQUEST_GET_STORED_MESSAGES)
        if async:
            dat[KeyType.request_async] = True
        return self._send_msg(dat)

    def send_message(self, msg, dst_user_id, is_anycast=False):
        """Send a message to the specified user_id

        Args:
            msg (dict): message to send
            dst_user_id (bytes): destination user_id
            is_anycast (bool): If true, the message is treated as an anycast message.
        Returns:
            bytes: query_id
        """
        dat = self._make_message_structure(MsgType.MESSAGE)
        dat[KeyType.destination_user_id] = dst_user_id
        dat[KeyType.message] = msg
        if is_anycast:
            dat[KeyType.is_anycast] = True
        return self._send_msg(dat)

    def start_receiver_loop(self):
        jobs = [gevent.spawn(self.receiver_loop)]
        #gevent.joinall(jobs)

    def receiver_loop(self):
        msg_parser = message_key_types.Message()
        try:
            while True:
                buf = self.connection.recv(8192)
                if len(buf) == 0:
                    break
                msg_parser.recv(buf)
                while True:
                    msg = msg_parser.parse()
                    if msg is None:
                        break
                    self.callback.dispatch(msg, msg_parser.payload_type)
        except Exception as e:
            self.logger.info("TCP disconnect: %s" % e)
            print(traceback.format_exc())
        self.connection.close()


class Callback:
    """Set of callback functions for processing received message

    If you want to implement your own way to process messages, inherit this class.
    """
    def __init__(self, log=None):
        self.logger = log
        self.client = None
        self.queue = queue.Queue()
        self.query_queue = dict()

    def set_logger(self, log):
        self.logger = log

    def set_client(self, client):
        self.client = client

    def create_queue(self, query_id):
        self.query_queue.setdefault(query_id, queue.Queue())

    def get_from_queue(self, query_id, timeout=None, no_delete=False):
        msg = self.query_queue[query_id].get(timeout=timeout)
        if not no_delete:
            del self.query_queue[query_id]
        return msg

    def dispatch(self, dat, payload_type):
        #self.logger.debug("Received: %s" % dat)
        if KeyType.command not in dat:
            self.logger.warn("No command exists")
            return
        if KeyType.query_id in dat and dat[KeyType.query_id] in self.query_queue:
            self.query_queue[dat[KeyType.query_id]].put(dat)
            return

        if dat[KeyType.command] == MsgType.RESPONSE_SEARCH_TRANSACTION:
            self.proc_resp_search_transaction(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_SEARCH_WITH_CONDITIONS:
            self.proc_resp_search_with_condition(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_TRAVERSE_TRANSACTIONS:
            self.proc_resp_traverse_transactions(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GATHER_SIGNATURE:
            self.proc_resp_gather_signature(dat)
        elif dat[KeyType.command] == MsgType.REQUEST_SIGNATURE:
            self.proc_cmd_sign_request(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_SIGNATURE:
            self.proc_resp_sign_request(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_INSERT:
            self.proc_resp_insert(dat)
        elif dat[KeyType.command] == MsgType.NOTIFY_INSERTED:
            self.proc_notify_inserted(dat)
        elif dat[KeyType.command] == MsgType.MESSAGE:
            self.proc_user_message(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_STATS:
            self.proc_resp_get_stats(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_DOMAINLIST:
            self.proc_resp_get_domainlist(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_USERS:
            self.proc_resp_get_userlist(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_NOTIFICATION_LIST:
            self.proc_resp_get_notificationlist(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_NODEID:
            self.proc_resp_get_node_id(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_CONFIG:
            self.proc_resp_get_config(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_SETUP_DOMAIN:
            self.proc_resp_domain_setup(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_CLOSE_DOMAIN:
            self.proc_resp_domain_close(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_STORED_MESSAGES:
            self.proc_resp_get_stored_message(dat)
        else:
            self.logger.warn("No method to process for command=%d" % dat[KeyType.command])

    def synchronize(self, timeout=None):
        """Wait for receiving message with a common queue

        Args:
            timeout (int): timeout for waiting a message in seconds
        Returns:
            dict: a received message
        """
        try:
            return self.queue.get(timeout=timeout)
        except:
            return None

    def sync_by_queryid(self, query_id, timeout=None, no_delete_q=False):
        """Wait for the message with specified query_id

        This method creates a queue for the query_id and waits for the response

        Args:
            query_id (byte): timeout for waiting a message in seconds
            timeout (int): timeout for waiting a message in seconds
            no_delete_q (bool): If True, the queue for the query_id remains after popping a message
        Returns:
            dict: a received message
        """
        try:
            if query_id not in self.query_queue:
                self.create_queue(query_id)
            return self.get_from_queue(query_id, timeout=timeout)
        except:
            return None

    def proc_cmd_sign_request(self, dat):
        """Callback for message REQUEST_SIGNATURE

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_resp_sign_request(self, dat):
        """Callback for message RESPONSE_SIGNATURE

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_resp_gather_signature(self, dat):
        """Callback for message RESPONSE_GATHER_SIGNATURE

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        if KeyType.status not in dat or dat[KeyType.status] < ESUCCESS:
            self.queue.put(dat)
            return
        format_type = dat[KeyType.transaction_data_format]
        if format_type in [bbclib.BBcFormat.FORMAT_BSON, bbclib.BBcFormat.FORMAT_BSON_COMPRESS_BZ2]:
            sigdata = bson.loads(dat[KeyType.signature])
        else:
            sigdata = dat[KeyType.signature]
        sig = bbclib.recover_signature_object(sigdata, format_type=format_type)
        self.queue.put({KeyType.status: ESUCCESS, KeyType.result: (dat[KeyType.ref_index], dat[KeyType.source_user_id], sig)})

    def proc_resp_insert(self, dat):
        """Callback for message RESPONSE_INSERT

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_notify_inserted(self, dat):
        """Callback for message NOTIFY_INSERTED

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_resp_search_with_condition(self, dat):
        """Callback for message RESPONSE_SEARCH_WITH_CONDITIONS

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_resp_search_transaction(self, dat):
        """Callback for message RESPONSE_SEARCH_TRANSACTION

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_resp_traverse_transactions(self, dat):
        """Callback for message RESPONSE_TRAVERSE_TRANSACTIONS

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_user_message(self, dat):
        """Callback for message MESSAGE

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_resp_domain_setup(self, dat):
        """Callback for message RESPONSE_SETUP_DOMAIN

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_resp_domain_close(self, dat):
        """Callback for message RESPONSE_CLOSE_DOMAIN

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_resp_get_config(self, dat):
        """Callback for message RESPONSE_GET_CONFIG

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_resp_get_domainlist(self, dat):
        """Callback for message RESPONSE_GET_DOMAINLIST

        List of domain_ids is queued rather than message itself.
        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        if KeyType.domain_list not in dat:
            self.queue.put(None)
            return
        self.queue.put(parse_one_level_list(dat[KeyType.domain_list]))

    def proc_resp_get_userlist(self, dat):
        """Callback for message RESPONSE_GET_USERS

        List of user_ids is queued rather than message itself.
        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        if KeyType.user_list not in dat:
            self.queue.put(None)
            return
        self.queue.put(parse_one_level_list(dat[KeyType.user_list]))

    def proc_resp_get_notificationlist(self, dat):
        """Callback for message RESPONSE_GET_NOTIFICATION_LIST

        List of user_ids in other core nodes is queued rather than message itself.
        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        if KeyType.notification_list not in dat:
            self.queue.put(None)
            return
        self.queue.put(parse_two_level_dict(dat[KeyType.notification_list]))

    def proc_resp_get_node_id(self, dat):
        """Callback for message RESPONSE_GET_NODEID

        Node_id is queued rather than message itself.
        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        if KeyType.node_id not in dat:
            self.queue.put(dat)
            return
        self.queue.put(dat[KeyType.node_id])

    def proc_resp_get_stats(self, dat):
        """Callback for message RESPONSE_GET_STATS

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        self.queue.put(dat)

    def proc_resp_get_stored_message(self, dat):
        """Callback for message RESPONSE_GET_STATS

        This method should be overridden if you want to process the message asynchronously.

        Args:
            dat (dict): received message
        """
        if KeyType.bulk_messages not in dat:
            self.queue.put(dat)
        else:
            msg_list = list()
            for dat2 in dat[KeyType.bulk_messages]:
                msg_list.append(msgpack.unpackb(dat2[8:]))
            dat[KeyType.bulk_messages] = msg_list
            self.queue.put(dat)
