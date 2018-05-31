# -*- coding: utf-8 -*-
import pytest

import subprocess
import pprint
import sys
sys.path.extend(["../"])
from bbc_simple.core import bbclib
from bbc_simple.core import bbc_stats
from bbc_simple.core.data_handler import DataHandler

user_id1 = bbclib.get_new_id("destination_id_test1")[:bbclib.DEFAULT_ID_LEN]
user_id2 = bbclib.get_new_id("destination_id_test2")[:bbclib.DEFAULT_ID_LEN]
domain_id = bbclib.get_new_id("test_domain")
asset_group_id1 = bbclib.get_new_id("asset_group_1")[:bbclib.DEFAULT_ID_LEN]
asset_group_id2 = bbclib.get_new_id("asset_group_2")[:bbclib.DEFAULT_ID_LEN]
txid1 = bbclib.get_new_id("dummy_txid_1")[:bbclib.DEFAULT_ID_LEN]
txid2 = bbclib.get_new_id("dummy_txid_2")[:bbclib.DEFAULT_ID_LEN]
keypair1 = bbclib.KeyPair()
keypair1.generate()

transactions = list()

data_handler =None
config = {
    "domains": {
        bbclib.convert_id_to_string(domain_id): {
            "db": {
                "db_addr": "127.0.0.1",
                "db_port": 3306,
                "db_user": "user",
                "db_pass": "pass",
                "db_rootpass": "password",
            },
        }
    }
}


def prepare_db():
    subprocess.call(["sh", "mysql_docker.sh"])


class DummyCore:
    class BBcNetwork:
        def __init__(self, core):
            self.core = core

    def __init__(self):
        self.networking = DummyCore.BBcNetwork(self)
        self.stats = bbc_stats.BBcStats()


class TestDataHandler(object):

    def test_01_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        #prepare_db()
        global data_handler
        dummycore = DummyCore()
        conf = config["domains"][bbclib.convert_id_to_string(domain_id)]
        data_handler = DataHandler(networking=dummycore.networking, config=conf, workingdir="testdir", domain_id=domain_id)
        global transactions
        for i in range(10):
            txobj = bbclib.BBcTransaction()
            evt = bbclib.BBcEvent()
            ast = bbclib.BBcAsset()
            ast.add(user_id=user_id1, asset_body=b'aaaaaa')
            evt.add(asset_group_id=asset_group_id1, asset=ast)
            rtn = bbclib.BBcRelation()
            ast2 = bbclib.BBcAsset()
            ast2.add(user_id=user_id2, asset_body=b'cccccccccc%d' % i)
            rtn.add(asset_group_id=asset_group_id2, asset=ast2)
            ptr = bbclib.BBcPointer()
            ptr.add(transaction_id=txid1)
            rtn.add(pointer=ptr)
            if i > 0:
                ptr = bbclib.BBcPointer()
                ptr.add(transaction_id=transactions[-1].transaction_id)
                rtn.add(pointer=ptr)
            wit = bbclib.BBcWitness()
            txobj.add(event=evt, relation=rtn, witness=wit)
            wit.add_witness(user_id1)
            sig = txobj.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                             private_key=keypair1.private_key, public_key=keypair1.public_key)
            txobj.add_signature(user_id=user_id1, signature=sig)
            txobj.digest()
            transactions.append(txobj)

    def test_02_check_table_existence(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = data_handler.db_adaptor.check_table_existence('transaction_table')
        assert len(ret) == 1
        ret = data_handler.db_adaptor.check_table_existence('asset_info_table')
        assert len(ret) == 1
        ret = data_handler.db_adaptor.check_table_existence('topology_table')
        assert len(ret) == 1

    def test_03_insert_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = data_handler.insert_transaction(transactions[0].serialize(), transactions[0])
        assert asset_group_id1 in ret and asset_group_id2 in ret

    def test_04_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret_txobj = data_handler.search_transaction(transaction_id=transactions[0].transaction_id)
        assert len(ret_txobj) == 1
        print(ret_txobj)

    def test_05_insert_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = data_handler.insert_transaction(transactions[0].serialize(), transactions[0])
        assert ret is None

    def test_06_remove_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print(transactions[0])
        print(transactions[0].transaction_id.hex())
        data_handler.remove(transaction_id=transactions[0].transaction_id)

        ret_txobj = data_handler.search_transaction(transaction_id=transactions[0].transaction_id)
        assert ret_txobj is None

    def test_07_insert_transactions(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(10):
            asset_files = {
                transactions[i].relations[0].asset.asset_id: transactions[i].relations[0].asset.asset_file,
            }
            ret = data_handler.insert_transaction(transactions[i].serialize(), transactions[i])
            assert asset_group_id1 in ret and asset_group_id2 in ret

    def test_08_search_transaction_by_user_id(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret_txobj = data_handler.search_transaction(asset_group_id=asset_group_id1, user_id=user_id1, count=0)
        assert len(ret_txobj) == 10
        pprint.pprint(ret_txobj, width=200)

    def test_09_search_transaction_topology(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = data_handler.search_transaction_topology(transactions[1].transaction_id)
        assert len(ret) == 2
        for i in range(2):
            assert ret[i][2] in [txid1, transactions[0].transaction_id]

        ret = data_handler.search_transaction_topology(transactions[1].transaction_id, traverse_to_past=False)
        assert len(ret) == 1
        assert ret[0][1] == transactions[2].transaction_id


if __name__ == '__main__':
    pytest.main()
