# -*- coding:utf-8 -*-

import ldap
import sys
import logging
import random

from flask import Flask, render_template, redirect
from flask import request, escape, session

app = Flask(__name__)

app.config['SECRET_KEY'] = 'test'

LDAPURL = 'ldap://localhost/'
SUFFIX = ',dc=example,dc=com'
BASE = 'cn=config'
SCOPE = ldap.SCOPE_BASE
FILTER = ""
ATTR = None
PARAMETER = 'olcLogLevel'

LOGINKEY = 'loginuser'
CSRFTOKEN = 'csrf_token'

logging.basicConfig(level=logging.DEBUG)


'''
乱数生成用関数
'''

@app.before_request
def csrf_protect():
    if request.method == "POST":
        logging.debug("csrf_protect")
        token = session.pop(CSRFTOKEN, None)
        if not token or token != request.form.get('csrf'):
            abort(403)


def create_token():
    if CSRFTOKEN not in session:
        session[CSRFTOKEN] = random.random()
    return session[CSRFTOKEN]

app.jinja_env.globals['csrftoken'] = create_token


@app.route("/login", methods=['GET', 'POST'])
def login():

    logging.debug("login page path:%s", request.path)
    logging.debug('sessiondata : %s', session)

    if request.method == 'POST':
        user = request.form.get('user')
        password = request.form.get('pass')

        ROOT = "cn=" + user + SUFFIX

        ld = ldapconnect(LDAPURL, ROOT, password)

        if not ld:
            logging.info('login faild')
            return render_template('loginform.html', err=True)
        else:
            logging.info('login success')
            logging.debug('form data %s',request.form)
            session[LOGINKEY] = request.form.get('user')
            session[CSRFTOKEN] = request.form.get('csrf')
            return redirect('/')

    if request.method == 'GET':
        return render_template('loginform.html', err=False)


@app.route("/", methods=['GET', 'POST'])
def index():
    logging.debug('config page path:%s', request.path)
    logging.debug('sessiondata : %s',  session)

    if LOGINKEY not in session:
            logging.info('not login')
            return redirect('login')


    logleveldata = {1: "trace", 2: "packets", 4: "args",
                    8: "conns", 16: "BER", 32: "filter",
                    64: "config", 128: "ACL", 256: "stats",
                    512: "stats2", 1024: "shell", 2048: "parse", 16384: "sync"}

    POSTDATA = ""

    username = session.get(LOGINKEY)
    ROOT = "cn=" + username.encode('utf-8') + SUFFIX
    PASS = "password"
    ld = ldapconnect(LDAPURL, ROOT, PASS)
    logging.debug('loginuser is [%s]', username)
    logging.debug('root is [%s]', ROOT)
    logging.debug('pass is [%s]', PASS)

    if request.method == 'POST':

        token = session.pop(CSRFTOKEN)

        logging.debug('requestkeys : %s',request.form)
        if str(token) != request.form.get('csrf'):
            logging.error("不正なアクセス")
            session.pop('loginuser',None)
            session.pop('csrf'.None)
            return redirect('/login')
        check = request.form.keys()
        logging.debug("POSTdata : %s",request.form)
        if 'logoutbutton' in request.form.keys():
            session.pop('loginuser', None)
            return redirect('/login')

        if 'sendbutton' in request.form.keys():
            '''
             チェックボックスの状態のみのデータにするため
             ボタンの値を除去
            '''
            check.remove('sendbutton')
            check.remove('csrf')

        if len(check) == 0:
            check.append('none')

        ldapmodify(ld, check)

    loglevelstate = ldapsearch(ld, BASE, SCOPE, PARAMETER)
    return render_template('ldapconfig.html', loglevels=logleveldata,
                           loglevelstate=loglevelstate, loginuser=username)




'''
ldapに接続する関数
'''


def ldapconnect(ldapurl, rootdn, password):
    try:
        ld = ldap.initialize(ldapurl)
        ld.simple_bind_s(rootdn, password)
    except ldap.INVALID_CREDENTIALS:
        logging.error("connect err : %s", sys.exc_info())
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
        logging.error("modify err : %s", sys.exc_info())
        return False

'''
PARAMETERの値をsearchする関数
'''


def ldapsearch(ld, base, scope, parameter):
    try:
        search_results = ld.search_ext_s(BASE, SCOPE)
    except:
        logging.error("search err : %s", sys.exc_info())
        return False

    datalist = search_results[0][1].get(PARAMETER, [])

    return datalist


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
