# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import sys
sys.path.extend(["../"])
from bbc_simple.core import bbclib
from bbc_simple.core.message_key_types import KeyType
from bbc_simple.core.bbc_error import *
from bbc_simple.core import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility, wait_check_result_msg_type


LOGLEVEL = 'debug'
LOGLEVEL = 'info'

core_num = 1
client_num = 5
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions = [None for i in range(client_num)]
transaction_dat = None

msg_processor = [None for i in range(client_num)]


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index

    def proc_user_message(self, dat):
        print("[%i] Recv Message from %s" % (self.idx, binascii.b2a_hex(dat[KeyType.source_user_id])))


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        global msg_processor
        prepare(core_num=core_num, client_num=client_num)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i)
            domain_setup_utility(i, domain_id)  # system administrator
        time.sleep(1)
        for i in range(client_num):
            msg_processor[i] = MessageProcessor(index=i)
            make_client(index=i, core_port_increment=0, callback=msg_processor[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()

    def test_01_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].register_to_core() # only client-0
        time.sleep(1)

    def test_02_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for k in range(5):
            for i in range(1, client_num):
                msg = "message %d (%d)" % (i, k)
                clients[0]['app'].send_message(msg, clients[i]['user_id'])
        time.sleep(1)

    def test_03_register_others(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            clients[i]['app'].register_to_core() # only client-0
        time.sleep(1)

    def test_04_bulk_read(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            query_id = clients[i]['app'].get_stored_messages(clients[i]['user_id'], async=False)
            dat = msg_processor[i].synchronize()
            assert KeyType.bulk_messages in dat
            assert len(dat[KeyType.bulk_messages]) == 5
            for dat2 in dat[KeyType.bulk_messages]:
                print("message:", dat2[KeyType.message])

    def test_05_unregister(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            clients[i]['app'].unregister_from_core()
        time.sleep(1)

    def test_06_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for k in range(5):
            for i in range(1, client_num):
                msg = "message %d (%d)" % (i, k)
                clients[0]['app'].send_message(msg, clients[i]['user_id'])
        time.sleep(1)

    def test_07_register_others(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            clients[i]['app'].register_to_core() # only client-0
        time.sleep(1)

    def test_08_bulk_read_async(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            query_id = clients[i]['app'].get_stored_messages(clients[i]['user_id'], async=True)
        print("=== wait for 5 seconds ===")
        time.sleep(5)


if __name__ == '__main__':
    pytest.main()
