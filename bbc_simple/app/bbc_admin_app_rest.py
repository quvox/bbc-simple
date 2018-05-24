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
import binascii
import hashlib
import bson
import os
import subprocess
import ast

import sys
sys.path.append("../../")
from argparse import ArgumentParser

from bbc_simple.core import bbc_app, bbclib
from bbc_simple.core.message_key_types import KeyType
from bbc_simple.logger.fluent_logger import get_fluent_logger

from argparse import ArgumentParser
from datetime import timedelta
from functools import update_wrapper
from flask import Flask, jsonify, request, make_response, current_app
from flask_cors import CORS

PID_FILE = "/tmp/bbc_admin_app_rest.pid"

http = Flask(__name__)
CORS(http)
flog = get_fluent_logger(name="bbc_admin_app_rest")
bbcapp = None


def crossdomain(origin=None, methods=None, headers=None,
                max_age=21600, attach_to_all=True,
                automatic_options=True):
    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, str):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, str):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods
        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))
            if not attach_to_all and request.method != 'OPTIONS':
                return resp
            h = resp.headers
            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)

    return decorator


@http.route('/domain_setup', methods=['POST', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def domain_setup():
    json_data = request.json
    domain_id = binascii.a2b_hex(json_data.get('domain_id'))
    config = json_data.get('config', None)
    qid = bbcapp.domain_setup(domain_id, config=config)
    retmsg = bbcapp.callback.sync_by_queryid(qid, timeout=5)
    if retmsg is None:
        return jsonify({'error': 'No response'}), 400
    msg = {'result': retmsg[KeyType.result]}
    if KeyType.reason in retmsg:
        msg['reason'] = retmsg[KeyType.reason]
    flog.debug({'cmd': 'domain_setup', 'result': retmsg[KeyType.result]})
    return jsonify(msg), 200


@http.route('/domain_close/<domain_id_str>', methods=['GET', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def domain_close(domain_id_str=None):
    try:
        domain_id = binascii.a2b_hex(domain_id_str)
    except:
        return jsonify({'error': 'invalid request'}), 500
    qid = bbcapp.domain_close(domain_id)
    retmsg = bbcapp.callback.sync_by_queryid(qid, timeout=5)
    if retmsg is None:
        return jsonify({'error': 'No response'}), 400
    msg = {'result': retmsg[KeyType.result]}
    if KeyType.reason in retmsg:
        msg['reason'] = retmsg[KeyType.reason]
    flog.debug({'cmd': 'domain_close', 'result': retmsg[KeyType.result]})
    return jsonify(msg), 200


@http.route('/get_node_id/<domain_id_str>', methods=['GET', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def get_node_id(domain_id_str=None):
    try:
        domain_id = binascii.a2b_hex(domain_id_str)
        bbcapp.set_domain_id(domain_id)
    except:
        return jsonify({'error': 'invalid request'}), 500
    qid = bbcapp.get_node_id()
    retmsg = bbcapp.callback.sync_by_queryid(qid, timeout=5)
    if retmsg is None:
        return jsonify({'error': 'No response'}), 400
    node_id = retmsg[KeyType.node_id].hex()
    msg = {'node_id': node_id}
    flog.debug({'cmd': 'get_node_id', 'node_id': node_id})
    return jsonify(msg), 200


@http.route('/get_bbc_config', methods=['GET', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def get_bbc_config():
    qid = bbcapp.get_bbc_config()
    retmsg = bbcapp.callback.sync_by_queryid(qid, timeout=5)
    if retmsg is None:
        return jsonify({'error': 'No response'}), 400
    config = retmsg[KeyType.bbc_configuration].decode()
    msg = {'config': config}
    flog.debug({'cmd': 'get_bbc_config', 'config': config})
    return jsonify(msg), 200


@http.route('/get_domain_list', methods=['GET', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def get_domain_list():
    flog.debug({'result': 'User registered successfully'})
    return jsonify({'message': 'User registered successfully'}), 200


@http.route('/get_user_list', methods=['GET', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def get_user_list():
    flog.debug({'result': 'User registered successfully'})
    return jsonify({'message': 'User registered successfully'}), 200


@http.route('/get_forwarding_list', methods=['GET', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def get_forwarding_list():
    flog.debug({'result': 'User registered successfully'})
    return jsonify({'message': 'User registered successfully'}), 200


@http.route('/get_notification_list', methods=['GET', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def get_notification_list():
    flog.debug({'result': 'User registered successfully'})
    return jsonify({'message': 'User registered successfully'}), 200


@http.route('/get_stats', methods=['GET', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type'])
def get_stats():
    qid = bbcapp.get_stats()
    retmsg = bbcapp.callback.sync_by_queryid(qid, timeout=5)
    if retmsg is None:
        return jsonify({'error': 'No response'}), 400
    stats = dict()
    for cat in retmsg[KeyType.stats].keys():
        newcat = cat.decode()
        stats[newcat] = dict()
        for item in retmsg[KeyType.stats][cat].keys():
            stats[newcat][item.decode()] = retmsg[KeyType.stats][cat][item]
    msg = {'stats': stats}
    flog.debug({'cmd': 'get_stats', 'stats': stats})
    return jsonify(msg), 200



def start_server(host="127.0.0.1", cport=9000, wport=3000):
    global bbcapp
    bbcapp = bbc_app.BBcAppClient(host=host, port=cport)
    #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    #context.load_cert_chain(os.path.join(argresult.ssl, "cert1.pem"), os.path.join(argresult.ssl, "privkey1.pem"))
    #http.run(host='0.0.0.0', port=argresult.waitport, ssl_context=context)
    http.run(host='0.0.0.0', port=wport)


def daemonize(pidfile=PID_FILE):
    """
    デーモン化する
    :param pidfile:
    :return:
    """
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        f2 = open(pidfile, 'w')
        f2.write(str(pid) + "\n")
        f2.close()
        os._exit(0)
    os.umask(0)


def parser():
    usage = 'python {} [--addr <string>] [--waitport <number>] [--coreport <number>] [-t <string>] [--ssl <string>] ' \
            '[--log <filename>] [--verbose_level <string>] [--daemon] [--kill] [--help]'.format(__file__)
    argparser = ArgumentParser(usage=usage)
    argparser.add_argument('--address', type=str, default="127.0.0.1", help='IP address of core node')
    argparser.add_argument('--waitport', type=int, default=3000, help='waiting http port')
    argparser.add_argument('--coreport', type=int, default=9000, help='TCP port of core node')
    argparser.add_argument('-t', '--token', type=str, default="keys/token", help='Key directory for token')
    argparser.add_argument('--ssl', type=str, default="keys/zettant.com", help='Key directory for SSL')
    argparser.add_argument('-l', '--log', type=str, default="-", help='log filename/"-" means STDOUT')
    argparser.add_argument('-d', '--daemon', action='store_true', help='run in background')
    argparser.add_argument('-k', '--kill', action='store_true', help='kill the daemon')
    argparser.add_argument('-v', '--verbose_level', type=str, default="debug",
                           help='log level all/debug/info/warning/error/critical/none')
    args = argparser.parse_args()
    return args


if __name__ == '__main__':
    argresult = parser()
    if argresult.kill:
        subprocess.call("kill `cat " + PID_FILE + "`", shell=True)
        subprocess.call("rm -f " + PID_FILE, shell=True)
        sys.exit(0)
    if not os.path.exists(os.path.join(argresult.ssl, "cert1.pem")):
        print("No cert file for SSL is found!")
        sys.exit(0)
    if not os.path.exists(os.path.join(argresult.ssl, "privkey1.pem")):
        print("No private key file for SSL is found!")
        sys.exit(0)
    if not os.path.exists(os.path.join(argresult.token, "server_privatekey.pem")):
        print("No private key for token is found!")
        sys.exit(0)
    if not os.path.exists(os.path.join(argresult.token, "server_publickey.pem")):
        print("No public key for token is found!")
        sys.exit(0)

    if argresult.daemon:
        daemonize()

    start_server(argresult.address, argresult.coreport, argresult.waitport)