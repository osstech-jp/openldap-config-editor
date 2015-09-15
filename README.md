テスト用 LDAP サーバー接続情報
===============================

URI:           ldap://localhost:389/
BIND_DN:       cn=admin,dc=example,dc=com
BIND_PASSWORD: password

ldapsearch(1) による取得例
===========================

    $ ldapsearch -x -W -D "cn=admin,dc=example,dc=com" -b cn=config -H ldap://localhost:389/
    Enter LDAP Password:     <-- パスワードを入力
    ...

python-ldap による取得例
===========================

    $ python
    >>> import ldap
    >>> ld = ldap.initialize('ldap://localhost:389')
    >>> ld.simple_bind_s('cn=admin,dc=example,dc=com', 'password')
    >>> ld.search_ext_s('cn=config', ldap.SCOPE_SUBTREE)

開発の流れ
==========

1. LDAP の設定情報 (olcLogLevel) を取得して、画面に表示できるようにする
2. LDAP の設定情報 (olcLogLevel) を取得して、画面に表示し、さらに更新もできるようにする
3. 2. の操作時、チェックボックスで選択できるようにする
    - 詳しくは 2. 終了後に説明
4. ログイン画面を用意する
5. olcLogLevel 以外の属性を取得して、画面に表示できるようにする
6. 見栄えを良くする
