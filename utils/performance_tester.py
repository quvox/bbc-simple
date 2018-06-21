#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
BBc-1 performance tester
"""
from argparse import ArgumentParser
import time
import sys
from functools import wraps

sys.path.append("..")
import bbc_simple.core.bbclib as bbclib
import bbc_simple.core.bbc_app as bbc_app

domain_id = bbclib.get_new_id("testdomain")
asset_group_id1 = bbclib.get_new_id("asset_group_1")[:bbclib.DEFAULT_ID_LEN]
asset_group_id2 = bbclib.get_new_id("asset_group_2")[:bbclib.DEFAULT_ID_LEN]

user_ids = list()
keypairs = list()


#FORMAT_TYPE = bbclib.BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB
#FORMAT_TYPE = bbclib.BBcFormat.FORMAT_BSON_COMPRESS_ZLIB
#FORMAT_TYPE = bbclib.BBcFormat.FORMAT_BINARY


def measure(func) :
    @wraps(func)
    def wrapper(*args, **kargs) :
        start = time.time()
        result = func(*args,**kargs)
        elapsed_time = time.time() - start
        print(f"{func.__name__}は{elapsed_time}秒かかりました")
        return result
    return wrapper


@measure
def make_transactions(fmt, count=1000):
    last_txid = None
    last_asid1 = None
    last_asid2 = None
    txobjs = list()
    for i in range(count):
        txobj = bbclib.make_transaction(relation_num=2, witness=True, format_type=fmt)
        bbclib.add_relation_asset(txobj, relation_idx=0, asset_group_id=asset_group_id1, user_id=user_ids[0],
                                  asset_body={"account": 10000, "type": "payment","amount": 1000, "message": "test"})

        if last_txid is not None:
            bbclib.add_relation_pointer(transaction=txobj, relation_idx=0,
                                        ref_transaction_id=last_txid, ref_asset_id=last_asid1)
        bbclib.add_relation_asset(txobj, relation_idx=1, asset_group_id=asset_group_id2, user_id=user_ids[1],
                                  asset_body={"account": 20000, "type": "receive", "amount": 500, "message": "aaa"})

        if last_txid is not None:
            bbclib.add_relation_pointer(transaction=txobj, relation_idx=1,
                                        ref_transaction_id=last_txid, ref_asset_id=last_asid2)
        for i in range(len(user_ids)):
            txobj.witness.add_witness(user_ids[i])
        for i in range(len(user_ids)):
            sig = txobj.sign(keypair=keypairs[i])
            txobj.witness.add_signature(user_id=user_ids[i], signature=sig)
        last_txid = txobj.digest()
        last_asid1 = txobj.relations[0].asset.asset_id
        last_asid2 = txobj.relations[1].asset.asset_id
        """
        d = txobj.serialize()
        txid = txobj.transaction_id
        for i, sig in enumerate(txobj.signatures):
            if not sig.verify(txid):
                print("bad format")

        x = bbclib.BBcTransaction(deserialize=d)
        for i, sig in enumerate(x.signatures):
            if not sig.verify(x.transaction_id):
                print("bad format")
        """
        txobjs.append(txobj)
    return txobjs


@measure
def insert_transactions(app, txobjs):
    for txobj in txobjs:
        app.insert_transaction(txobj)


def parser():
    usage = 'python {} [-a <string>] [--coreport <number>] [-l <number>] [-c <number>] [--help]'.format(__file__)
    argparser = ArgumentParser(usage=usage)
    argparser.add_argument('-a', '--address', type=str, default='localhost', help='bbc_core address')
    argparser.add_argument('--port', type=int, default=9000, help='bbc_core port')
    argparser.add_argument('-l', '--loop', type=int, default=1000, help='loop count')
    argparser.add_argument('-c', '--clients', type=int, default=3, help='loop count')
    argparser.add_argument('-t', '--type', type=int, default=0, help='format_type')
    args = argparser.parse_args()
    return args


if __name__ == "__main__":
    parsed_args = parser()
    for i in range(parsed_args.clients):
        user_ids.append(bbclib.get_new_id("user_id_%d" % i)[:bbclib.DEFAULT_ID_LEN])
        keypairs.append(bbclib.KeyPair())
        keypairs[i].generate()

    app = bbc_app.BBcAppClient(host=parsed_args.address, port=parsed_args.port, multiq=False, id_length=bbclib.DEFAULT_ID_LEN)

    app.set_user_id(user_ids[0])
    app.register_to_core()
    app.set_domain_id(domain_id)
    app.domain_setup(domain_id)
    dat = app.callback.synchronize()

    print("***** format_type = %d ******" % parsed_args.type)
    txobjs = make_transactions(fmt=parsed_args.type, count=parsed_args.loop)

    insert_transactions(app, txobjs)

