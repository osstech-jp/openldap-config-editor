# -*- coding:utf-8 -*-

import ldap
import sys
import logging
import random
import ConfigParser

from flask import Flask, render_template, redirect
from flask import request, escape, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test'

inifile = ConfigParser.SafeConfigParser()
inifile.read('./config.ini')

LDAP = {'URL': inifile.get('ldapconnect','URL'),
        'SUFFIX': inifile.get('ldapconnect','SUFFIX'),
        'BASE': 'cn=config',
        'SCOPE': ldap.SCOPE_BASE,
        'PARAMETER': 'olcLogLevel'}



USER = 'user'
PASS = 'pass'

CSRFTOKEN = 'csrf_token'

logging.basicConfig(level=logging.DEBUG, format = "line:%(lineno)3d - %(message)s")


'''
乱数生成用関数
'''

@app.before_request
def csrf_protect():
    if request.method == "POST":
        logging.debug("csrf_protect")
        token = session.pop(CSRFTOKEN, None)
        if not token or str(token) != request.form.get('csrf'):
            logging.error('不正なアクセス')
            abort(403)
        logging.debug('csrf clear\n')


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
        username = request.form.get('user').encode('utf-8')
        password = request.form.get('pass').encode('utf-8')

        logging.debug("before ldapconnect")
        ld = ldapconnect(LDAP.get('URL'), username, password)
        logging.debug("after ldapconnect")

        if not ld:
            logging.info('login faild')
            return render_template('loginform.html', err=True)
        else:
            logging.info('login success')
            logging.debug('form data %s',request.form)
            session[USER] = request.form.get('user')
            session[PASS] = request.form.get('pass')
            return redirect('/')

    if request.method == 'GET':
        return render_template('loginform.html', err=False)


@app.route("/", methods=['GET', 'POST'])
def index():
    logging.debug('config page path:%s', request.path)
    logging.debug('sessiondata : %s',  session)

    if USER not in session:
            logging.info('not login')
            return redirect('/login')


    logleveldata = {1: "trace", 2: "packets", 4: "args",
                    8: "conns", 16: "BER", 32: "filter",
                    64: "config", 128: "ACL", 256: "stats",
                    512: "stats2", 1024: "shell", 2048: "parse", 16384: "sync"}

    POSTDATA = ""
    username = session.get(USER).encode('utf-8')
    password = session.get(PASS).encode('utf-8')
    ld = ldapconnect(LDAP.get('URL'), username, password)

    logging.debug('loginuser is [%s]', username)
    logging.debug('pass is [%s]', password)

    if request.method == 'POST':
        
        check = request.form.keys()
        logging.debug("POSTdata : %s",request.form)
        if 'logoutbutton' in request.form.keys():
            session.pop(USER)

            return redirect('/login')

        if 'sendbutton' in request.form.keys():
            '''
             チェックボックスの状態のみのデータにするため
             ボタンとCSRFの値を除去
            '''
            check.remove('sendbutton')
            check.remove('csrf')

        if len(check) == 0:
            check.append('none')

        ldapmodify(ld, check, LDAP.get('BASE'), LDAP.get('PARAMETER'))

    loglevelstate = ldapsearch(ld, LDAP.get('BASE'), LDAP.get('SCOPE'), LDAP.get('PARAMETER'))
    return render_template('ldapconfig.html', loglevels=logleveldata,
                           loglevelstate=loglevelstate, loginuser=username)




'''
ldapに接続する関数
'''


def ldapconnect(ldapurl, username, password):
    rootdn = "cn=" + username + "," + LDAP.get('SUFFIX')
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


def ldapmodify(ld, datas, base, parameter):
    modlist = []
    for data in datas:
        if len(modlist) == 0:
            modlist.append((ldap.MOD_REPLACE, parameter, data))
        else:
            modlist.append((ldap.MOD_ADD, parameter, data))

    try:
        ld.modify_ext_s(base, modlist)
    except:
        logging.error("modify err : %s", sys.exc_info())
        logging.error("modlist : %s",modlist)
        return False

'''
PARAMETERの値をsearchする関数
'''


def ldapsearch(ld, base, scope, parameter):
    try:
        search_results = ld.search_ext_s(base,scope)
    except:
        logging.error("search err : %s", sys.exc_info())
        return False

    datalist = search_results[0][1].get(parameter, [])

    return datalist


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
