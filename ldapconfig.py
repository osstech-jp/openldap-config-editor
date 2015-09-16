# -*- coding:utf-8 -*-

import ldap
import sys
import logging
import random
import ConfigParser

from flask import Flask, render_template, redirect
from flask import request, escape, session
from collections import OrderedDict

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test'

inifile = ConfigParser.SafeConfigParser()
inifile.read('./config.ini')

LDAP = {'URL': inifile.get('ldapconnect','URL'),
        'BASE': ['cn=config',
                 'olcDatabase={-1}frontend,cn=config',
                 'olcDatabase={1}hdb,cn=config'],
        'SCOPE': ldap.SCOPE_BASE,
        'PARAMETER': 'olcLogLevel'}

# 順序付き辞書型に変換
USERS = OrderedDict(inifile.items('Users'))



USER = 'user'
PASS = 'pass'

CSRFTOKEN = 'csrf_token'

PARAMETERS = ['olcLogLevel','olcTimeLimit','olcSizeLimit']

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
    logging.debug('USERS is [%s]',USERS)
    if request.method == 'POST':
        username = request.form.get('user').encode('utf-8')
        password = request.form.get('pass').encode('utf-8')


        ld = ldapconnect(LDAP.get('URL'), username, password)

        if not ld:
            logging.info('login faild')
            return render_template('loginform.html', users=USERS, err=True)
        else:
            logging.info('login success')
            logging.debug('form data %s',request.form)
            session[USER] = request.form.get('user')
            session[PASS] = request.form.get('pass')
            return redirect('/')

    if request.method == 'GET':
        return render_template('loginform.html', users=USERS, err=False)
        

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

    modify_auth = True
    username = session.get(USER).encode('utf-8')
    password = session.get(PASS).encode('utf-8')
    ld = ldapconnect(LDAP.get('URL'), username, password)

    if request.method == 'POST':
        
        check = request.form.keys()
        postkeys = check
        logging.debug("POSTdata : %s",request.form)
        if 'logoutbutton' in postkeys:
            session.pop(USER)
            session.pop(PASS)
            return redirect('/login')

        if 'sendbutton' in postkeys:

            modloglevel = []
            for key in postkeys:
                if key in logleveldata.values():
                    modloglevel.append(key)
            if len(modloglevel) == 0:
                modloglevel.append('none')

            timelimit = request.form.get('timelimit')
            if timelimit == 'on':
                modtimelimit = ['unlimited']
            else:
                modtimelimit = [timelimit.encode('utf-8')]

            sizelimit = request.form.get('sizelimit')
            if sizelimit == 'on':
                modsizelimit = ['unlimited']
            else:
                modsizelimit = [sizelimit.encode('utf-8')]

            print modloglevel
            print modtimelimit
            print modsizelimit
            
            modify_auth = ldapmodify(ld, modloglevel, LDAP.get('BASE')[0], PARAMETERS[0])
            modify_auth = ldapmodify(ld, modtimelimit, LDAP.get('BASE')[1], PARAMETERS[1])

    configoptions = ldapsearch(ld, LDAP.get('BASE')[0], LDAP.get('SCOPE'))
    databaseoptions = ldapsearch(ld, LDAP.get('BASE')[1], LDAP.get('SCOPE'))
    examples = ldapsearch(ld, LDAP.get('BASE')[2], LDAP.get('SCOPE'))

    if not configoptions:
        return render_template('ldapconfig.html',read_auth=False,loginuser=username)
    else:
        loglevelstate = configoptions.get(PARAMETERS[0],[])
        timelimit = databaseoptions.get(PARAMETERS[1],['unlimited'])[0]
        sizelimit = databaseoptions.get(PARAMETERS[2],['unlimited'])[0]

        return render_template('ldapconfig.html',
                           loglevels=logleveldata, loglevelstate=loglevelstate,
                           timelimit=timelimit, sizelimit=sizelimit,
                           databaseoptions=databaseoptions,
                           configoptions=configoptions,
                           loginuser=username,
                           read_auth=configoptions, modify_auth=modify_auth)




'''
ldapに接続する関数
'''


def ldapconnect(ldapurl, username, password):
    rootdn = USERS.get(username) 
    try:
        ld = ldap.initialize(ldapurl)
        ld.simple_bind_s(rootdn, password)
    except (ldap.INVALID_CREDENTIALS, ldap.INVALID_DN_SYNTAX) as e:
        logging.error("connect err : %s", e)
        return False
    return ld

'''
ldapmodifyする関数
'''


def ldapmodify(ld, datas, base, parameter):
    try:
        modlist = [(ldap.MOD_REPLACE, parameter, datas)]
        ld.modify_ext_s(base, modlist)
    except ldap.INSUFFICIENT_ACCESS as e:
        logging.error("modify err : %s", sys.exc_info())
        logging.error("modlist : %s",modlist)
        return False
    return True

'''
PARAMETERの値をsearchする関数
'''


def ldapsearch(ld, base, scope):
    try:
        search_results = ld.search_ext_s(base,scope)
    except ldap.NO_SUCH_OBJECT as e:
        logging.error("search err : %s", e)
        return False
    datalist = search_results[0][1]

    return datalist


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
