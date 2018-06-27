Simple version of BBc-1
====
この実装は、[BBc-1](https://github.com/beyond-blockchain/bbc1) version 1.0
をより簡素化した実装である。BBc-1で用意されている様々なオプションの中からいくつかの機能を排除し、またサードパーティのサービスを利用することで簡素化を行った。
基本的なコンセプトはBBc-1と全く同様であり、トランザクションデータは完全互換である。また、bbc\_app.pyのAPIも変更はない（不要になったものは廃止した）。

具体的なBBc-1との違いは以下の点である。
* トランザクションデータのデータフォーマットを独自バイナリ方式を排除し、bson (binary JSON)のみの対応とした
  * Web系のシステムに適用しやすくするため
* トランザクションデータ保存用DBおよび補助DBをcore nodeごとに保持するのではなく、外部DBサーバを利用するようにした（EXTERNALモードのみ）
  * すべてのcore nodeが一つのDBクラスタを利用することが可能
*  core nodeでアセットファイルを管理する機能（Storage）を廃止した（EXTERNALモードのみ）
  * アセットファイルは、すべてトランザクションの中に含めるか、またはアプリケーション自身が個別に管理する
* core node間のメッセージングを、TCPの独自コネクションから、[Redis](https://redis.io)に変更した
  * クライアントが未接続のときに配送されたメッセージを保存しておいて、接続したときにまとめて配送することが可能になった
  * ネットワーク制御のコードサイズが激減した
  * オリジナルBBc-1と比較して、Anycastのみ不可
* 履歴交差機能を廃止した
  * 内部運用する際に、システム管理を簡素化するため。別途アプリケーションを開発すれば実施可能
* core node内部で改ざんを検知する機能を一部廃止した
  * 改ざん検知用の管理アプリケーションによって定期的に確認するようにする
* bbc\_app.pyをラップしたRESTサーバ機能を実装した
* core node間、core-client間のコネクション暗号化機能(node\_key)、および管理用コマンド用のdomain\_keyを廃止した
  * core node自体のシステムがクラウドの中だけで構築される場合を想定した
  * core node間はredisにTLSを適用すれば暗号化可能
  * core-client間は、RESTサーバとクライアント間をSSLで接続すれば暗号化可能
* 管理用utilityを廃止した
  * ほとんど必要なくなったため
* 暗号鍵(ECC)の対応アルゴリズムを拡充した
　* ECDSA_P256v1
* 各種idの長さを32バイト(256bit)以下に圧縮できるようにした
  * ただしdomain_idだけは他ドメインとの整合性を取るために32バイトのままとした


# 実行環境

* Python
    - Python 3.5.0 or later
    - pipenv を推奨するが、virtualenvでもよい
        - pipenvを使うなら ```export PIPENV_VENV_IN_PROJECT=true``` を .bash_profileに記載するとローカルディレクトリに環境を構築できるようになる

* macOS の Homebrewでpythonとopensshビルド環境をインストールする
    ```
    brew install libtool automake python3 pipenv
    ```

* Linux (Ubuntu 16.04 LTS)でpythonとopensshビルド環境をインストールする
    ```
    sudo apt-get install -y git tzdata openssh-server python3 python3-dev libffi-dev net-tools autoconf automake libtool libssl-dev make
    pip install pipenv
    ```


# インストール
1. opensslをビルドするためのツールをインストールする (libtool, automake)
2. python と pipをインストールする
3. このプロジェクトをcloneする
4. OpenSSLベースの library をビルドする
    ```
    sh prepare.sh
    ```
5. 関連するpythonモジュールをインストールする。
    ```
    pipenv install
    pipenv shell
    ```
    Pipfileがpython 3.6用に設定されているので、もしpython3.6以外の環境の場合は、上記のpipenvの代わりに下記を実行する。
    ```
    pipenv install -r requirements.txt
    pipenv shell
    ``` 

# 実行方法
ワーキングディレクトリ（デフォルトは.bbc1/）のconfig.jsonで、DBおよびRedisサーバの接続先を指定する。デフォルト値はローカルホストになる。
なお、scripts/start-docker-services.sh を実行すればMySQLサーバとRedisサーバのdockerコンテナが立ち上がるので、すぐ利用できる（もちろんdockerのインストールは事前に必要である）。
これらのサーバを起動したあと、下記コマンドでbbc\_core.pyを起動すればよい。

```
cd bbc_simple/core
python bbc_core.py
```

# テストコード
tests/の下にあるテストコードはpytestで実行できる。APIの利用方法はテストコードを参考にするとよい。なお大部分はBBc-1のテストコードと同一であり、一部だけ修正したものがほとんどである。
