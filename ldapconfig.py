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

    #####################
    # ldapサーバーへ接続#
    #####################
    ld = ldapconnect(LDAPURL,ROOTDN,PASS)
    #############
    # POSTの処理#
    #############
    if request.method == 'POST':
        # POSTされたデータの取得
        CHECK = request.form.keys()
        print "checkboxLOG"
        # チェックされた値のリストを作成
        CHECK.remove('sendbutton')
        print CHECK

        # チェックボックスが空ならnoneを指定 
        if len(CHECK) == 0:
            CHECK.append('none')
        
        # CHECKの値でmodify
        ldapmodify(ld,CHECK)
                               
    ############
    # GETの処理#
    ############

    ###############
    # ページの表示#
    ###############
    
    # データの取得
    loglevel = ldapsearch(ld,BASE,SCOPE,PARAMETER)
    print "loglevel"
    print loglevel

    # logleveldataと比較し、TrueFalseの一覧リストを作成
    for loop in range(0,len(logleveldata)):
        if len(logleveldata[len(logleveldata)-1]) < 3:
            logleveldata[loop].append(logleveldata[loop][1] in loglevel)
        else :
            logleveldata[loop][2] = (logleveldata[loop][1] in loglevel)
    
    # ページヘの出力
    return render_template('ldapconfig.html',loglevels=logleveldata, errlist=errlist)




####################
#ldapに接続する関数#
####################
def ldapconnect(ldapurl,rootdn,password):
    try :
        ld=ldap.initialize(ldapurl)
        ld.simple_bind_s(rootdn,password)
    except:
        return "<h1> Err! </h1>\
                <p>{err}</p>".format(err=sys.exc_info())
  
    return ld

####################
#ldapmodifyする関数#
####################
def ldapmodify(ld,datas):
    # modlistの作成
    modlist=[]
    for data in datas:
        if len(modlist) == 0:
            modlist.append( (ldap.MOD_REPLACE,PARAMETER,data) )
        else:
            modlist.append( (ldap.MOD_ADD,PARAMETER,data) )
    print "modlist is {modlist}".format(modlist=modlist)

    # 作成したmodデータを用いてModify
    try :
        ld.modify_ext_s(BASE,modlist)
    except:
        return "<h1> Err! </h1>\
                <p>{err}</p>".format(err=sys.exc_info())


###############################
#PARAMETERの値をsearchする関数#
###############################
def ldapsearch(ld,base,scope,parameter):
    # 全属性の取得
    try:
        search_results = ld.search_ext_s(BASE,SCOPE)
    except:
        return "<h1> Err! </h1>\
                <p>{err}</p>".format(err=sys.exc_info())

    # PARAMETERの値を取得
    datalist = search_results[0][1].get(PARAMETER,[])

    return datalist


if __name__=='__main__':
    app.run(debug=True,host='0.0.0.0')
