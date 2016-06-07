#!/usr/bin/python
# -*- coding: utf-8 -*-
#COPYRIGHTED UNDER BEERWARE LICENSE
#/*
# * ----------------------------------------------------------------------------
# * "THE BEER-WARE LICENSE" (Revision 42):
# * <flipchan@riseup.net> wrote this file. As long as you retain this notice you
# * can do whatever you want with this stuff. If we meet some day, and you think
# * this stuff is worth it, you can buy me a beer in return Filip kälebo
# * ----------------------------------------------------------------------------
# */

import flask, MySQLdb
import base64, base58 #bitcoin runs with base58
import gnupg, sys
from os import urandom 
from werkzeug import secure_filename
import ecdsa 
import hashlib
from flask.ext.scrypt import generate_random_salt, generate_password_hash
from datetime import timedelta #to not define as datetime.timedelta
import os,sys #duck
import datetime

#notes
#add namecoin support??
#http://namecoin.info/


#gnupg , use root???or usr
gpg = gnupg.GPG(homedir='/root/.gnupg')    #this depends
#gpg = gnupg.GPG(gnupghome='/root/.gnupg') #	         on ur gpg version/os
gpg.encoding = 'utf-8'

reload( sys )
sys.setdefaultencoding('utf-8')

bloggen = flask.Flask(__name__) #app3n
bloggen.config['ALLOWED_EXTENSIONS'] = ''
bloggen.config['UPLOAD_FOLDER'] = 'static/avatars/'

#define some k3ys
bloggen.secret_key = 'urkey'

hash1 = 'urkey1'
hash2 = 'urkey2'
hash3 = 'urkey3'

#30 min for perm session
bloggen.permanent_session_lifetime = timedelta(minutes=30)

#mysql connect
db = MySQLdb.connect(host='localhost', user='', passwd='', db='bloggen')
#perm session in 30min
bloggen.permanent_session_lifetime = timedelta(minutes=30)
#flask.session.permanent = True
#blog db
#create database bloggen;
#use bloggen;
#create table bloggen(
#user_id int(11) not null AUTO_INCREMENT,
#name varchar(200) not null,
#des longtext not null,
#pgp_fingerprint text not null,
#password text not null,
#pgp text not null,
#role text not null,
#joined date not null,
#btcaddress text not null,
#email text not null,
#PRIMARY KEY(user_id)
#);
#
#

#define anonymous role och anti-csrf skyddet
@bloggen.before_request
def csrf_protect():
    if flask.request.method == 'POST':
        token = flask.session.pop('_doda_csrf', None)
        if not token or token != flask.request.form.get('_doda_csrf'):
            return 'error with your request'
#def make_anon():                                        nope this aint good for now
#    if 'role' or 'user' or 'admin' not in session:
#        session['role'] = 'anonymous'
#        session['nick'] = 'anonymous user'
#def ses_perm():
   # session.permanent = True
   # bloggen.permanent_session_lifetime = timedelta(minutes=30)
def gen_token():
    if '_doda_csrf' not in flask.session:
        flask.session['_doda_csrf'] = base64.b64encode(urandom(67))
    return flask.session['_doda_csrf']
    
bloggen.jinja_env.globals['doda_csrf'] = gen_token

@bloggen.route('/')
def index():
    #om man e inloggad kmr man t sin main page
    if flask.session.has_key('role') and flask.session['online']:
        return flask.redirect(flask.url_for(str(flask.session['role'])))
    
    return flask.render_template('index.html')



@bloggen.route('/main/<nick>')
def user(nick):
    if not flask.session:
        return flask.redirect(flask.url_for('login'))
    
    
    return flask.render_template('user.html', emnick = flask.escape(flask.session['nick']),)

@bloggen.route('/admin')
def admin():
    if flask.session.has_key('role') and flask.session['role'] == 'admin':
        return flask.render_template('admin.html')

    return flask.redirect(flask.url_for('nono'))

@bloggen.route('/readme')
def readme():
	return ''' 
<html>
<head>
<title> About  </title>
</head>
<center>
<h3>About this blog app</h3>

</html>
	'''
@bloggen.route('/login', methods=['POST', 'GET'])
def login():
    error = False
    #if flask.session.has_key('im_online') and flask.session["im_online"]:
     #   return flask.redirect(flask.url_for(str(flask.session['role'])))

    #if not flask.session.has_key('im_online'):
	#return flask.render_template('login.html')

    if flask.request.method == 'POST':
	nickname = flask.request.form['username']
	password = flask.request.form['Password']	     
	#correct login?
 	curlee = db.cursor()
	hashone = generate_password_hash(password, hash1)
	hashtwo = generate_password_hash(hashone, hash2)
	hashthree = generate_password_hash(hashtwo, hash3)
	hashedpasswd = hashthree
	curlee.execute('select password from bloggen where name=%s', (nickname,))
	crr = db.cursor()
	crr.execute('select role from bloggen where name=%s', (nickname,))
	roler = crr.fetchone()
	result = curlee.fetchone()
	cuuu = db.cursor()
	cuuu.execute('select pgp from bloggen where name=%s', (nickname,))
	lpgp = cuuu.fetchone()
	
	if lpgp == 'Yes':
	    shelloo = base64.b64encode(urandom(16)) #base64 encode bytes from the kernel to use as auth for 2 factor auth code
	    data = shelloo
	    xaa = db.cursor()
	    xaa.execute('select pgp_fingerprint from bloggen where nick=%s', (nickname,))
	    thefing = xaa.fetchone()
	    encrypted_ascii_data = gpg.encrypt(data, thefing)
	    sig2 = gpg.sign(hello, default_key=lpgp, passphrase='passwd')
	    sigmsg = sig2
	    if flask.request.method == 'POST':
		if secret == secdata:
		    flask.session['im_online'] = True
		    flask.session['nick'] = nickname
		    flask.session['role'] = roler[0]
		    return flask.redirect(flask.url_for(str(flask.session["role"])))		    

	    return flask.render_template('2factor.html', user=nickname, thecode=sigmsg)	
	else:
		return ''
	if hashespasswd == result[0]:
	        flask.session['im_online'] = True
		flask.session['nick'] = nickname
		flask.session['role'] = roler[0]
		return flask.redirect(flask.url_for(str(flask.session["role"])))
	#if usr got pgp go to 2 factor
#	elif lpgp:
		


	return flask.render_template('login.html')
    
    
    return flask.render_template('login.html', error=error)



@bloggen.route('/signup', methods=['POST', 'GET'])
def signup():
    error = False
    #if flask.session:
    #    return flask.redirect(flask.url_for(str(flask.session['role'])))

    #if not flask.session:
	#return flask.render_template('signup.html')

    if flask.request.method == 'POST':

	nickname = flask.request.form['username']
	password = flask.request.form['Password']
	vpassword = flask.request.form['vpassword']
        #hash it 3 times with with scrypt
	pgp_fingerprint = flask.request.form['pgpid']
	email = flask.request.form['email']
	pgp = flask.request.form['pgpkey']
	 #verify password
	if vpassword == password:
	    hashone = generate_password_hash(password, hash1)
	    hashtwo = generate_password_hash(hashone, hash2)
	    hashthree = generate_password_hash(hashtwo, hash3)
	    hashedpasswd = hashthree
        #bitcoin it
	privkey = urandom(32).encode('hex')
	mypriv = privkey
	sk = ecdsa.SigningKey.from_string(mypriv.decode('hex'), curve = ecdsa.SECP256k1)
	vk = sk.verifying_key
	den_publika = ('\00' + vk.to_string()).encode('hex')#00 for att adda addressen t main network
        #u can verify to c that this piece of code works great https://www.bitaddress.org/
        #time to print out an address
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(den_publika.decode('hex')).digest())
	ripemd160.digest()
	today = datetime.date.today()
	mixit = '\34' + ripemd160.digest()
	checksum = hashlib.sha256(hashlib.sha256(mixit).digest()).digest()[:4]
	binaryaddress_som_vi_gen = mixit + checksum
	bitcoinaddress = base58.b58encode(binaryaddress_som_vi_gen)
       #insert it
        ba = bitcoinaddress
        cur = db.cursor()
	#if pgp_fingerprint
	if not pgp:
	    pgp = 'no'
	    pgp_fingerprint = 'no'
	role = 'user' #we only want ppl to become usrs n not admins
        cur.execute('insert into bloggen (name, password, email, pgp, btcaddress, joined, role, pgp_fingerprint) values (%s, %s, %s, %s, %s, %s, %s, %s)', (nickname, hashedpasswd, email, pgp, ba, today, role, pgp_fingerprint))
        db.commit()
			#btcaddress	 
	return '''
			Welcome ''' + nickname + ''' your private bitcoin key is ''' + privkey + ''' 
			remeber to save it cuz we dont, u need it to controll ur bitcoins , login at /login
			'''
    #else:
			#error = 'ur password doesnt match'
			#return flask.render_template('signup.html', error=error)
    
		    
			#return flask.render_template('signup.html')
    return flask.render_template('signup.html', error=error)

@bloggen.route('/search/<st>', methods=['GET'])
def search(st):
    if flask.session:
        return flask.render_template('search.html', search=s)
    
    return flask.redirect(flask.url_for('nono'))

@bloggen.route('/rss', methods=['GET'])
def rss():

	return flask.render_template('rss.xml')


@bloggen.route('/blog/<nickname>')
def blogs(nickname):
    
    
    return flask.render_template('blog.html')


@bloggen.route('/nono')
def nono():
    return '''

No no no thats forbidden..
    
    '''

@bloggen.route('/logout')
def logout():
    flask.session["present"] = False
    flask.session['online'] = False
    flask.session.pop('nick', None)
    flask.session.pop("username", None)
    flask.session.pop("role", None)

    return'''
    <center>
    c ya later!
    '''


@bloggen.errorhandler(404)
def fyraifyra(error):
    return '''
<html>    

<title>404</title>
   
<body>
   <center>
   <pre>
Glitch in matrix?<br>   
   cuz u are on a 404 page try to go back and try again
   </pre>
   </body>
    
 </html>   
    '''



#run it in debug mode for testing remove in a real deployment
if __name__ == '__main__':
    bloggen.run(debug=True,port=1337)
