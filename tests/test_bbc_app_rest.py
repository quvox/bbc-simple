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
tx1 = None
tx2 = None

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


def make_many_transactions(num):
    transactions1 = [None for i in range(num)]
    transactions2 = [None for i in range(num)]
    transactions1[0] = bbclib.make_transaction(relation_num=1, witness=True, format_type=bbclib.BBcFormat.FORMAT_BSON)
    bbclib.add_relation_asset(transactions1[0], relation_idx=0, asset_group_id=asset_group_id,
                              user_id=user_id1, asset_body=b'transaction1_0')
    transactions1[0].witness.add_witness(user_id1)
    sig = transactions1[0].sign(keypair=keypair1)
    transactions1[0].witness.add_signature(user_id1, sig)

    transactions2[0] = bbclib.make_transaction(event_num=1, witness=True, format_type=bbclib.BBcFormat.FORMAT_BSON)
    transactions2[0].events[0].add(mandatory_approver=user_id2)
    bbclib.add_event_asset(transactions2[0], event_idx=0, asset_group_id=asset_group_id,
                           user_id=user_id2, asset_body=b'transaction2_0')
    transactions2[0].witness.add_witness(user_id2)
    sig = transactions2[0].sign(keypair=keypair2)
    transactions2[0].witness.add_signature(user_id=user_id2, signature=sig)

    for i in range(1, num):
        k = i - 1
        transactions1[i] = bbclib.make_transaction(relation_num=1, witness=True, format_type=bbclib.BBcFormat.FORMAT_BSON)
        bbclib.add_relation_asset(transactions1[i], 0, asset_group_id=asset_group_id, user_id=user_id1,
                                  asset_body=b'transaction1_%d' % i)
        bbclib.add_relation_pointer(transactions1[i], 0, ref_transaction_id=transactions1[k].transaction_id,
                                    ref_asset_id=transactions1[k].relations[0].asset.asset_id)
        transactions1[i].witness.add_witness(user_id1)
        sig = transactions1[i].sign(keypair=keypair1)
        transactions1[i].witness.add_signature(user_id1, sig)

        transactions2[i] = bbclib.make_transaction(event_num=1, witness=True, format_type=bbclib.BBcFormat.FORMAT_BSON)
        transactions2[i].events[0].add(mandatory_approver=user_id2)
        bbclib.add_event_asset(transactions2[i], event_idx=0, asset_group_id=asset_group_id,
                               user_id=user_id2, asset_body=b'transaction2_%d' % i)
        transactions2[i].witness.add_witness(user_id2)
        bbclib.add_reference_to_transaction(transactions2[i], asset_group_id, transactions2[k], 0)
        sig = transactions2[i].sign(keypair=keypair2)
        transactions2[i].witness.add_signature(user_id=user_id2, signature=sig)
        if i == 9:
            bbclib.add_reference_to_transaction(transactions2[i], asset_group_id, transactions2[5], 0)
            sig = transactions2[i].sign(keypair=keypair2)
            transactions2[i].references[0].add_signature(user_id=user_id2, signature=sig)
    return transactions1, transactions2


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
            'source_user_id': user_id1.hex(),
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
            'source_user_id': user_id1.hex(),
            'transaction_id': txid.hex()
        }
        req = requests.post(BASE_URL+'/search_transaction/'+domain_id.hex(),
                            json=parameter,
                            headers={u'Content-Type': u'application/json'})
        assert req.status_code == 200
        transaction = bson.loads(base64.b64decode(req.json()['transaction_bson']))
        print(transaction)

    def test_11_insert_transactions_and_traverse(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global tx1, tx2
        tx1, tx2 = make_many_transactions(10)
        for tx in tx1+tx2:
            bsonobj = tx.serialize_bson(no_header=True)

            parameter = {
                'source_user_id': user_id1.hex(),
                'transaction_bson': base64.b64encode(bsonobj).decode()
            }
            req = requests.post(BASE_URL+'/insert_transaction/'+domain_id.hex(),
                                json=parameter,
                                headers={u'Content-Type': u'application/json'})
            assert req.status_code == 200
            print("response:", req.json())

    def test_12_traverse(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        parameter = {
            'source_user_id': user_id1.hex(),
            'transaction_id': tx1[0].transaction_id.hex(),
            'direction': 0,
            'hop_count': 5
        }
        req = requests.post(BASE_URL+'/traverse_transactions/'+domain_id.hex(),
                            json=parameter,
                            headers={u'Content-Type': u'application/json'})
        assert req.status_code == 200
        jsondat = req.json()
        print("all_included?:", jsondat['include_all_flag'])
        for i, level in enumerate(jsondat['transaction_tree']):
            print("****Level:", i)
            for txdat in level:
                transaction = bson.loads(base64.b64decode(txdat))
                print(transaction)

    def test_12_traverse_reverse(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        parameter = {
            'source_user_id': user_id1.hex(),
            'transaction_id': tx1[2].transaction_id.hex(),
            'direction': 1,
            'hop_count': 4
        }
        req = requests.post(BASE_URL+'/traverse_transactions/'+domain_id.hex(),
                            json=parameter,
                            headers={u'Content-Type': u'application/json'})
        assert req.status_code == 200
        jsondat = req.json()
        print("all_included?:", jsondat['include_all_flag'])
        for i, level in enumerate(jsondat['transaction_tree']):
            print("****Level:", i)
            for txdat in level:
                transaction = bson.loads(base64.b64decode(txdat))
                print(transaction)

    def test_13_traverse_not_found(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        parameter = {
            'source_user_id': user_id2.hex(),
            'transaction_id': tx2[0].transaction_id.hex(),
            'user_id': user_id1.hex(),
            'direction': 0,
            'hop_count': 4
        }
        req = requests.post(BASE_URL+'/traverse_transactions/'+domain_id.hex(),
                            json=parameter,
                            headers={u'Content-Type': u'application/json'})
        assert req.status_code == 400
        print(req.json())

    def test_14_traverse(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        parameter = {
            'source_user_id': user_id2.hex(),
            'transaction_id': tx2[0].transaction_id.hex(),
            'user_id': user_id2.hex(),
            'direction': 0,
            'hop_count': 4
        }
        req = requests.post(BASE_URL+'/traverse_transactions/'+domain_id.hex(),
                            json=parameter,
                            headers={u'Content-Type': u'application/json'})
        assert req.status_code == 200
        jsondat = req.json()
        print("all_included?:", jsondat['include_all_flag'])
        for i, level in enumerate(jsondat['transaction_tree']):
            print("****Level:", i)
            for txdat in level:
                transaction = bson.loads(base64.b64decode(txdat))
                print(transaction)

    def test_20_close_domain(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        req = requests.get(BASE_URL+'/domain_close/'+domain_id.hex())
        assert req.status_code == 200
        print("response:", req.json())


if __name__ == '__main__':
    pytest.main()

