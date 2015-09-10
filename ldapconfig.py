#-*- coding: utf-8 -*-

import ldap
import sys
import csv

from flask import Flask, render_template
from flask import request

app = Flask(__name__)

LDAPURL='ldap://localhost/'
ROOTDN=',dc=example,dc=com'
USER = ''
PASS=''
BASE='cn=config'
SCOPE=ldap.SCOPE_BASE
FILTER=""
ATTR=None
logleveldata=[["1","trace"],["2","packets"],["4","args"],["8","conns"],["16","BER"],\
              ["32","filter"],["64","config"],["128","ACL"],["256","stats"],\
              ["512","stats2"],["1024","shell"],["2048","parse"]]
PARAMETER = 'olcLogLevel'

@app.route("/" , methods=['GET','POST'])
def login():
    print "LOGIN"
    err = False
    jump= False
    
    if request.method == 'POST':
        # ユーザー名、パスワードの取得
        USER = request.form.get('user').decode('utf-8')
        PASS = request.form.get('pass').decode('utf-8')

        ROOT = "cn=" + USER + ROOTDN.decode('utf-8')

        # 入力されたデータでldapサーバーへ接続
        ld = ldapconnect(LDAPURL,ROOT,PASS)
        
        # 認証に失敗した場合エラーを出力
        if ld == -1:
            err = True
            print "Err"
            return render_template('loginform.html',err = err, jump = jump)
        # 成功した場合ldapConfigへ移動
        else :
            print "Success"
            jump = True
            return render_template('loginform.html',err = err, jump = jump)
    if request.method == 'GET':
        return render_template('loginform.html',err = err, jump = jump)
       

@app.route("/ldapconfig" , methods=['GET' , 'POST'])
def index() :
    POSTDATA = ""
    errlist=[]

    #####################
    # ldapサーバーへ接続#
    #####################
    ROOT = "cn=admin" + ROOTDN.decode('utf-8')
    PASS = "password"
    ld = ldapconnect(LDAPURL,ROOT,PASS)

    #############
    # POSTの処理#
    #############
    if request.method == 'POST':
        # POSTされたデータの取得
        CHECK = request.form.keys()
        # チェックされた値のリストを作成
        CHECK.remove('button')

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
        return -1
  
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

    # 作成したmodデータを用いてModify
    try :
        ld.modify_ext_s(BASE,modlist)
    except:
        return "<h1> ModifyErr! </h1><p>{err}</p>".format(err=sys.exc_info())


###############################
#PARAMETERの値をsearchする関数#
###############################
def ldapsearch(ld,base,scope,parameter):
    # 全属性の取得
    try:
        search_results = ld.search_ext_s(BASE,SCOPE)
    except:
        return "<h1> SearchErr! </h1> <p>{err}</p>".format(err=sys.exc_info())

    # PARAMETERの値を取得
    datalist = search_results[0][1].get(PARAMETER,[])

    return datalist


if __name__=='__main__':
    app.run(debug=True,host='0.0.0.0')
