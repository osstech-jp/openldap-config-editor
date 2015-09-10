#-*- coding: utf-8 -*-

import ldap
import sys
import csv

from flask import Flask, render_template
from flask import request

app = Flask(__name__)

LDAPURL='ldap://localhost/'
ROOTDN='cn=admin,dc=example,dc=com'
PASS='password'
BASE='cn=config'
SCOPE=ldap.SCOPE_BASE
FILTER=""
ATTR=None
logleveldata=[["1","trace"],["2","packets"],["4","args"],["8","conns"],["16","BER"],\
              ["32","filter"],["64","config"],["128","ACL"],["256","stats"],\
              ["512","stats2"],["1024","shell"],["2048","parse"]]
PARAMETER = 'olcLogLevel'


@app.route("/" , methods=['GET' , 'POST'])
def index():

    POSTDATA = ""
    errlist=[]
    # POSTされたデータチェック
    if request.method == 'POST':
        # POSTされたデータの取得
        POSTDATA =request.form['adddata'].encode('utf-8')
        
        # カンマ区切りで分割
        splitdata =  [x.strip() for x in POSTDATA.split(',')]
        print splitdata

        # POSTされたデータのチェック
        for item in splitdata:
            # logleveldataに存在しなければerrlistに追加していく
            if not item in [x[1] for x in logleveldata]:
                errlist.append(item)
        print POSTDATA + " is {result}".format(result=errlist)


    try:

        # ldapサーバーへ接続
        ld=ldap.initialize(LDAPURL)
        ld.simple_bind_s(ROOTDN,PASS)
         # 全属性の取得
        search_results = ld.search_ext_s(BASE,SCOPE)
        # loglevelの取得
        loglevel=search_results[0][1].get(PARAMETER,[])

        # errlistにデータが無ければmodify
        if len(errlist) == 0 and request.method == 'POST':
            mod_attr=[]
            for item in splitdata:
                if len(mod_attr) == 0:
                    mod_attr.append( (ldap.MOD_REPLACE,PARAMETER,item) )
                else:
                    mod_attr.append( (ldap.MOD_ADD,PARAMETER,item) )
            print "mod_attr is {data}".format(data=mod_attr)

           # 作成したmodデータを用いてModify 
            ld.modify_ext_s(BASE,mod_attr)
                    
            # データの再取得
            search_results = ld.search_ext_s(BASE,SCOPE)
            loglevel=search_results[0][1].get(PARAMETER,[])

    except:
        return "<h1>Error!!</h1><p>{err}</p>".format(err=sys.exc_info())


    for loop in range(0,len(logleveldata)):
        if len(logleveldata[len(logleveldata)-1]) < 3:
            logleveldata[loop].append(logleveldata[loop][1] in loglevel)
        else :
            logleveldata[loop][2] = (logleveldata[loop][1] in loglevel)
    # ページヘの出力
    return render_template('ldapconfig.html',loglevels=logleveldata, errlist=errlist)



if __name__=='__main__':
    app.run(debug=True,host='0.0.0.0')
