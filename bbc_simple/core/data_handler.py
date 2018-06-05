# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 quvox.net

This code is based on that in bbc-1 (https://github.com/beyond-blockchain/bbc1.git)
"""
import mysql.connector
import traceback

import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc_simple.core import bbclib
from bbc_simple.core.message_key_types import to_2byte, PayloadType, KeyType
from bbc_simple.logger.fluent_logger import get_fluent_logger

transaction_tbl_definition = [
    ["transaction_id", "BLOB"], ["transaction_data", "BLOB"],
]

asset_info_definition = [
    ["id", "INTEGER"],
    ["transaction_id", "BLOB"], ["asset_group_id", "BLOB"], ["asset_id", "BLOB"], ["user_id", "BLOB"],
]

topology_info_definition = [
    ["id", "INTEGER"], ["base", "BLOB"], ["point_to", "BLOB"]
]


class DataHandler:
    """DB and storage handler"""

    def __init__(self, networking=None, default_config=None, config=None, workingdir=None, domain_id=None):
        self.networking = networking
        self.core = networking.core
        self.stats = networking.core.stats
        self.logger = get_fluent_logger(name="data_handler")
        self.domain_id = domain_id
        self.domain_id_str = bbclib.convert_id_to_string(domain_id)[:16]
        self.config = config
        self.working_dir = workingdir
        self.db_adaptor = None
        self._db_setup(default_config)

    def _db_setup(self, default_config):
        """Setup DB"""
        if 'db' in self.config:
            dbconf = self.config['db']
            db_name = dbconf.get("db_name", self.domain_id_str)
            db_addr = dbconf.get("db_addr", "127.0.0.1")
            db_port = dbconf.get("db_port", 3306)
            db_user = dbconf.get("db_user", "user")
            db_pass = dbconf.get("db_pass", "pass")
            db_rootpass = dbconf.get("db_rootpass", "password")
        else:
            db_name = default_config.get("db_name", self.domain_id_str)
            db_addr = default_config.get("db_addr", "127.0.0.1")
            db_port = default_config.get("db_port", 3306)
            db_user = default_config.get("db_user", "user")
            db_pass = default_config.get("db_pass", "pass")
            db_rootpass = default_config.get("db_rootpass", "password")

        self.db_adaptor = MysqlAdaptor(self, db_name=db_name, server_info=(db_addr, db_port, db_user, db_pass))

        self.db_adaptor.open_db(db_rootpass)
        self.db_adaptor.create_table('transaction_table', transaction_tbl_definition, primary_key=0, indices=[0])
        self.db_adaptor.create_table('asset_info_table', asset_info_definition, primary_key=0, indices=[0, 1, 2, 3, 4])
        self.db_adaptor.create_table('topology_table', topology_info_definition, primary_key=0, indices=[0, 1, 2])

    def exec_sql(self, sql=None, args=(), commit=False, fetch_one=False):
        """Execute sql sentence

        Args:
            sql (str): SQL string
            args (list): Args for the SQL
            commit (bool): If True, commit is performed
            fetch_one (bool): If True, fetch just one record
        Returns:
            list: list of records
        """
        self.stats.update_stats_increment("data_handler", "exec_sql", 1)
        #print("sql=", sql)
        #if len(args) > 0:
        #    print("args=", args)
        try:
            if len(args) > 0:
                self.db_adaptor.db_cur.execute(sql, args)
            else:
                self.db_adaptor.db_cur.execute(sql)
            if commit:
                self.db_adaptor.db.commit()
                ret = None
            else:
                if fetch_one:
                    ret = self.db_adaptor.db_cur.fetchone()
                else:
                    ret = self.db_adaptor.db_cur.fetchall()
        except:
            self.logger.error(traceback.format_exc())
            traceback.print_exc()
            self.stats.update_stats_increment("data_handler", "fail_exec_sql", 1)
            return None
        if ret is None:
            return []
        else:
            return list(ret)

    def get_asset_info(self, txobj):
        """Retrieve asset information from transaction object

        Args:
            txobj (BBcTransaction): transaction object to analyze
        Returns:
            list: list of list [asset_group_id, asset_id, user_id, False, file_digest]
        """
        info = list()
        for idx, evt in enumerate(txobj.events):
            ast = evt.asset
            if ast is not None:
                info.append((evt.asset_group_id, ast.asset_id, ast.user_id))
        for idx, rtn in enumerate(txobj.relations):
            ast = rtn.asset
            if rtn.asset is not None:
                info.append((rtn.asset_group_id, ast.asset_id, ast.user_id))
        return info

    def _get_topology_info(self, txobj):
        """Retrieve topology information from transaction object

        This method returns (from, to) list that describe the topology of transactions

        Args:
            txobj (BBcTransaction): transaction object to analyze
        Returns:
            list: list of tuple (base transaction_id, pointing transaction_id)
        """
        info = list()
        for reference in txobj.references:
            info.append((txobj.transaction_id, reference.transaction_id))  # (base, point_to)
        for idx, rtn in enumerate(txobj.relations):
            for pt in rtn.pointers:
                info.append((txobj.transaction_id, pt.transaction_id))  # (base, point_to)
        return info

    def insert_transaction(self, txdata, txobj=None):
        """Insert transaction data and its asset files

        Either txdata or txobj must be given to insert the transaction.

        Args:
            txdata (bytes): serialized transaction data
            txobj (BBcTransaction): transaction object to insert
        Returns:
            set: set of asset_group_ids in the transaction
        """
        self.stats.update_stats_increment("data_handler", "insert_transaction", 1)
        if txobj is None:
            txobj = self.core.validate_transaction(txdata)
            if txobj is None:
                return None
        if not self._insert_transaction_into_a_db(txobj):
            return None

        asset_group_ids = set()
        for asset_group_id, asset_id, user_id in self.get_asset_info(txobj):
            asset_group_ids.add(asset_group_id)
        return asset_group_ids

    def _insert_transaction_into_a_db(self, txobj):
        """Insert transaction data into the transaction table of the specified DB

        Args:
            txobj (BBcTransaction): transaction object to insert
        Returns:
            bool: True if successful
        """
        #print("_insert_transaction_into_a_db: for txid =", txobj.transaction_id.hex())
        if txobj.transaction_data is None:
            txobj.serialize()
        ret = self.exec_sql(sql="INSERT INTO transaction_table VALUES (%s,%s)" % (self.db_adaptor.placeholder,
                                                                                  self.db_adaptor.placeholder),
                            args=(txobj.transaction_id, txobj.transaction_data), commit=True)
        if ret is None:
            return False

        for asset_group_id, asset_id, user_id in self.get_asset_info(txobj):
            self.exec_sql(sql="INSERT INTO asset_info_table(transaction_id, asset_group_id, asset_id, user_id) "
                              "VALUES (%s, %s, %s, %s)" % (
                              self.db_adaptor.placeholder, self.db_adaptor.placeholder,
                              self.db_adaptor.placeholder, self.db_adaptor.placeholder),
                          args=(txobj.transaction_id, asset_group_id, asset_id, user_id), commit=True)
        for base, point_to in self._get_topology_info(txobj):
            self.exec_sql(sql="INSERT INTO topology_table(base, point_to) VALUES (%s, %s)" %
                              (self.db_adaptor.placeholder, self.db_adaptor.placeholder),
                          args=(base, point_to), commit=True)
            #print("topology: base:%s, point_to:%s" % (base.hex(), point_to.hex()))
        return True

    def remove(self, transaction_id, txobj=None):
        """Delete all data regarding the specified transaction_id

        This method requires either transaction_id or txobj.

        Args:
            transaction_id (bytes): target transaction_id
            txobj (BBcTransaction): transaction object to remove
        """
        if transaction_id is None:
            return
        if txobj is None:
            txdata = self.exec_sql(sql="SELECT * FROM transaction_table WHERE transaction_id = %s" %
                                   self.db_adaptor.placeholder, args=(transaction_id,))
            txobj = bbclib.BBcTransaction(deserialize=txdata[0][1])
        elif txobj.transaction_id != transaction_id:
            return
        self._remove_transaction(txobj)

    def _remove_transaction(self, txobj):
        """Remove transaction from DB"""
        #print("_remove_transaction: for txid =", txobj.transaction_id.hex())
        self.exec_sql(sql="DELETE FROM transaction_table WHERE transaction_id = %s" % self.db_adaptor.placeholder,
                      args=(txobj.transaction_id,), commit=True)
        for base, point_to in self._get_topology_info(txobj):
            self.exec_sql(sql="DELETE FROM topology_table WHERE base = %s AND point_to = %s" %
                          (self.db_adaptor.placeholder,self.db_adaptor.placeholder),
                          args=(base, point_to), commit=True)

    def search_transaction(self, transaction_id=None, asset_group_id=None, asset_id=None, user_id=None, count=1):
        """Search transaction data

        When Multiple conditions are given, they are considered as AND condition.

        Args:
            transaction_id (bytes): target transaction_id
            asset_group_id (bytes): asset_group_id that target transactions should have
            asset_id (bytes): asset_id that target transactions should have
            user_id (bytes): user_id that target transactions should have
            count (int): The maximum number of transactions to retrieve
        Returns:
            dict: mapping from transaction_id to serialized transaction data
            dict: dictionary of {asset_id: content} for the transaction
        """
        if transaction_id is not None:
            txinfo = self.exec_sql(
                sql="SELECT * FROM transaction_table WHERE transaction_id = %s" % self.db_adaptor.placeholder,
                args=(transaction_id,))
            if len(txinfo) == 0:
                return None
        else:
            sql = "SELECT * from asset_info_table WHERE "
            conditions = list()
            if asset_group_id is not None:
                conditions.append("asset_group_id = %s " % self.db_adaptor.placeholder)
            if asset_id is not None:
                conditions.append("asset_id = %s " % self.db_adaptor.placeholder)
            if user_id is not None:
                conditions.append("user_id = %s " % self.db_adaptor.placeholder)
            sql += "AND ".join(conditions) + "ORDER BY id DESC"
            if count > 0:
                if count > 20:
                    count = 20
                sql += " limit %d" % count
            sql += ";"
            args = list(filter(lambda a: a is not None, (asset_group_id, asset_id, user_id)))
            ret = self.exec_sql(sql=sql, args=args)
            txinfo = list()
            for record in ret:
                tx = self.exec_sql(
                    sql="SELECT * FROM transaction_table WHERE transaction_id = %s" % self.db_adaptor.placeholder,
                    args=(record[1],))
                if tx is not None and len(tx) == 1:
                    txinfo.append(tx[0])

        result_txobj = dict()
        for txid, txdata in txinfo:
            txobj = bbclib.BBcTransaction(deserialize=txdata)
            result_txobj[txid] = txobj
        return result_txobj

    def search_transaction_topology(self, transaction_id, traverse_to_past=True):
        """Search in topology info

        Args:
            transaction_id (bytes): base transaction_id
            traverse_to_past (bool): True: search backward (to past), False: search forward (to future)
        Returns:
            list: list of records of topology table
        """
        if transaction_id is None:
            return None
        if traverse_to_past:
            return self.exec_sql(sql="SELECT * FROM topology_table WHERE base = %s" %
                                 self.db_adaptor.placeholder, args=(transaction_id,))

        else:
            return self.exec_sql(sql="SELECT * FROM topology_table WHERE point_to = %s" %
                                 self.db_adaptor.placeholder, args=(transaction_id,))


class DbAdaptor:
    """Base class for DB adaptor"""
    def __init__(self, handler=None, db_name=None):
        self.handler = handler
        self.db = None
        self.db_cur = None
        self.db_name = "dom"+db_name
        self.placeholder = ""

    def open_db(self, rootpass):
        """Open the DB"""
        pass

    def create_table(self, tbl, tbl_definition, primary_key=0, indices=[]):
        """Create a table"""
        pass

    def check_table_existence(self, tblname):
        """Check whether the table exists or not"""
        pass


class MysqlAdaptor(DbAdaptor):
    """DB adaptor for MySQL"""
    def __init__(self, handler=None, db_name=None, server_info=None):
        super(MysqlAdaptor, self).__init__(handler, db_name)
        self.placeholder = "%s"
        self.db_addr = server_info[0]
        self.db_port = server_info[1]
        self.db_user = server_info[2]
        self.db_pass = server_info[3]

    def open_db(self, rootpass):
        """Open the DB"""
        db = None
        db_cur = None
        try:
            db = mysql.connector.connect(
                host=self.db_addr, port=self.db_port,
                user="root", password=rootpass, charset='utf8'
            )
            db_cur = db.cursor(buffered=True)
            db_cur.execute("show databases like '%s'" % self.db_name)

            if len(db_cur.fetchall()) == 0:
                db_cur.execute("create database %s" % self.db_name)
                grant_sql = "GRANT ALL ON %s.* TO '%s'@'%%';" % (self.db_name, self.db_user)
                db_cur.execute(grant_sql)
        except Exception as e:
            self.handler.logger.error(e)
        finally:
            db_cur.close()
            db.close()

        self.db = mysql.connector.connect(
            host=self.db_addr,
            port=self.db_port,
            db=self.db_name,
            user=self.db_user,
            password=self.db_pass,
            charset='utf8'
        )
        self.db_cur = self.db.cursor(buffered=True)

    def create_table(self, tbl, tbl_definition, primary_key=0, indices=[]):
        """Create a table

        Args:
            tbl (str): table name
            tbl_definition (list): schema of the table [["column_name", "data type"],["colmun_name", "data type"],,]
            primary_key (int): index (column) of the primary key of the table
            indices (list): list of indices to create index
        """
        if len(self.check_table_existence(tbl)) == 1:
            return
        sql = "CREATE TABLE %s " % tbl
        sql += "("
        defs = list()
        for d in tbl_definition:
            if d[0] == "id":
                defs.append("%s %s AUTO_INCREMENT NOT NULL" % (d[0], d[1]))
            else:
                defs.append("%s %s" % (d[0], d[1]))
        sql += ",".join(defs)
        if tbl_definition[primary_key][1] in ["BLOB", "TEXT"]:
            sql += ", PRIMARY KEY (%s(32))" % tbl_definition[primary_key][0]
        else:
            sql += ", PRIMARY KEY (%s)" % tbl_definition[primary_key][0]
        sql += ") CHARSET=utf8 ENGINE=MyISAM;"
        self.handler.exec_sql(sql=sql, commit=True)
        for idx in indices:
            if tbl_definition[idx][1] in ["BLOB", "TEXT"]:
                self.handler.exec_sql(sql="ALTER TABLE %s ADD INDEX (%s(32));" % (tbl, tbl_definition[idx][0]), commit=True)
            else:
                self.handler.exec_sql(sql="ALTER TABLE %s ADD INDEX (%s);" % (tbl, tbl_definition[idx][0]), commit=True)

    def check_table_existence(self, tblname):
        """Check whether the table exists or not"""
        sql = "show tables from %s like '%s';" % (self.db_name, tblname)
        return self.handler.exec_sql(sql=sql)
