# -*- coding: utf-8 -*-
import pytest

import requests
import base64
import bson
import threading
import time
import shutil

import sys
sys.path.extend(["../"])
from bbc_simple.core import bbclib
from testutils import prepare, start_core_thread
import bbc_simple.app.bbc_app_rest as bbc_rest

LOGLEVEL = 'debug'
LOGLEVEL = 'info'

core_num = 1
client_num = 1
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")[:bbclib.DEFAULT_ID_LEN]

user_id1 = bbclib.get_new_id("user1")[:bbclib.DEFAULT_ID_LEN]
user_id2 = bbclib.get_new_id("user2")[:bbclib.DEFAULT_ID_LEN]
keypair1 = bbclib.KeyPair()
keypair1.generate()
keypair2 = bbclib.KeyPair()
keypair2.generate()

txid = None
asid = None

BASE_URL = "http://localhost:3000"


def make_transaction():
    txobj = bbclib.make_transaction(event_num=2, witness=True, format_type=bbclib.BBcFormat.FORMAT_BSON)
    txobj.events[0].add(reference_index=0, mandatory_approver=user_id1)
    bbclib.add_event_asset(txobj, event_idx=0, asset_group_id=asset_group_id,
                           user_id=user_id1, asset_body=b'123456')
    bbclib.add_event_asset(txobj, event_idx=1, asset_group_id=asset_group_id,
                           user_id=user_id1, asset_body=b'abcdefg')
    txobj.witness.add_witness(user_id1)
    sig = txobj.sign(keypair=keypair1)
    txobj.add_signature(user_id=user_id1, signature=sig)
    global txid, asid
    txid = txobj.digest()
    asid = txobj.events[0].asset.asset_id
    return txobj


def start_server():
    bbc_rest.start_server()


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        shutil.rmtree(".bbc1-9000")
        prepare(core_num=core_num, client_num=client_num)
        for i in range(core_num):
            start_core_thread(index=i)
        time.sleep(1)
        th = threading.Thread(target=start_server)
        th.setDaemon(True)
        th.start()
        time.sleep(1)

    def test_01_creat_domain(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        parameter = {
            'domain_id': domain_id.hex()
        }
        req = requests.post(BASE_URL+'/domain_setup',
                            json=parameter,
                            headers={u'Content-Type': u'application/json'})
        assert req.status_code == 200
        print("response:", req.json())

    def test_02_insert_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        tx = make_transaction()
        bsonobj = tx.serialize_bson(no_header=True)

        parameter = {
            'user_id': user_id1.hex(),
            'transaction_bson': base64.b64encode(bsonobj).decode()
        }
        req = requests.post(BASE_URL+'/insert_transaction/'+domain_id.hex(),
                            json=parameter,
                            headers={u'Content-Type': u'application/json'})
        assert req.status_code == 200
        print("response:", req.json())

    def test_03_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        parameter = {
            'user_id': user_id1.hex(),
            'transaction_id': txid.hex()
        }
        req = requests.post(BASE_URL+'/search_transaction/'+domain_id.hex(),
                            json=parameter,
                            headers={u'Content-Type': u'application/json'})
        assert req.status_code == 200
        transaction = bson.loads(base64.b64decode(req.json()['transaction_bson']))
        print(transaction)

    def test_20_close_domain(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        req = requests.get(BASE_URL+'/domain_close/'+domain_id.hex())
        assert req.status_code == 200
        print("response:", req.json())


if __name__ == '__main__':
    pytest.main()

