# -*- coding:utf-8 -*-

import ldap
import sys

from flask import Flask, render_template
from flask import request
from flask import redirect

app = Flask(__name__)

LDAPURL = 'ldap://localhost/'
DOMAIN = ',dc=example,dc=com'
BASE = 'cn=config'
SCOPE = ldap.SCOPE_BASE
FILTER = ""
ATTR = None
PARAMETER = 'olcLogLevel'


@app.route("/", methods=['GET', 'POST'])
def login():

    err = False

    if request.method == 'POST':
        user = request.form.get('user')
        password = request.form.get('pass')

        ROOT = "cn=" + user + DOMAIN

        ld = ldapconnect(LDAPURL, ROOT, password)

        if not ld:
            err = True
            return render_template('loginform.html', err=err,)
        else:
            return redirect('/ldapconfig')

    if request.method == 'GET':
        return render_template('loginform.html', err=False,)


@app.route("/ldapconfig", methods=['GET', 'POST'])
def index():
    logleveldata = [["1", "trace"], ["2", "packets"], ["4", "args"],
                    ["8", "conns"], ["16", "BER"], ["32", "filter"],
                    ["64", "config"], ["128", "ACL"], ["256", "stats"],
                    ["512", "stats2"], ["1024", "shell"], ["2048", "parse"]]

    POSTDATA = ""

    ROOT = "cn=admin" + DOMAIN.decode('utf-8')
    PASS = "password"
    ld = ldapconnect(LDAPURL, ROOT, PASS)

    if request.method == 'POST':
        check = request.form.keys()
        # チェックボックスの状態を取得するため
        # すべてのkeyを取得し、buttonのデータを削除
        check.remove('button')

        if len(check) == 0:
            check.append('none')

        ldapmodify(ld, check)

    loglevel = ldapsearch(ld, BASE, SCOPE, PARAMETER)

    for loop in range(0, len(logleveldata)):
        if len(logleveldata[len(logleveldata)-1]) < 3:
            logleveldata[loop].append(logleveldata[loop][1] in loglevel)
        else:
            logleveldata[loop][2] = (logleveldata[loop][1] in loglevel)

    return render_template('ldapconfig.html', loglevels=logleveldata)


'''
ldapに接続する関数
'''


def ldapconnect(ldapurl, rootdn, password):
    try:
        ld = ldap.initialize(ldapurl)
        ld.simple_bind_s(rootdn, password)
    except:
        print sys.exc_info()
        return False

    return ld

'''
ldapmodifyする関数
'''


def ldapmodify(ld, datas):
    modlist = []
    for data in datas:
        if len(modlist) == 0:
            modlist.append((ldap.MOD_REPLACE, PARAMETER, data))
        else:
            modlist.append((ldap.MOD_ADD, PARAMETER, data))

    try:
        ld.modify_ext_s(BASE, modlist)
    except:
        print sys.exc_info()
        return False

'''
PARAMETERの値をsearchする関数
'''


def ldapsearch(ld, base, scope, parameter):
    try:
        search_results = ld.search_ext_s(BASE, SCOPE)
    except:
        print sys.exc_info()
        return False

    datalist = search_results[0][1].get(PARAMETER, [])

    return datalist


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
