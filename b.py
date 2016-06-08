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
gpg = gnupg.GPG(homedir='/home/gibba/.gnupg')    #this depends
#gpg = gnupg.GPG(gnupghome='/root/.gnupg') #	         on ur gpg version/os
gpg.encoding = 'utf-8'

reload( sys ) #live debugging 
sys.setdefaultencoding('utf-8')

bloggen = flask.Flask(__name__) #app3n
bloggen.config['ALLOWED_EXTENSIONS'] = ''
bloggen.config['UPLOAD_FOLDER'] = 'static/avatars/'

#define some k3ys
bloggen.secret_key = 'TDm3dYbdMVjhV6G3K5HJ6GY65yNakQchKfeQOIBp+DjnaAeeuwzTyUUH+S3F9LHTU/Mq4fHeXojVHc6ppO6OUrHUfQ'

hash1 = 'ebgLMawd1gUw2ggKPDs/7OIgVfArUyMir2nH11gdAIqfPU2KRDYTen8tmjUnAP4xCXgNxmVIllzrTYezlDTyPzbbcg'
hash2 = 'ftyLNB/h9ZDfv/bWF5/tLXK4I/ZSqLDJPV9Nfw48/I5obBqLcdLGArUnbHZP0vYhgz7yh0YXAuGAUkEKSpD386XuAA'
hash3 = 'XFMGOHC9ME+OeXU3A9vyDJfqIZp60tZ7qQYmyDHgUhafd7qpsUtCO7vIDFHopG0V9fH3XJuL01H0SRgcDaOdgCIE+Q'

#30 min for perm session
bloggen.permanent_session_lifetime = timedelta(minutes=30)

blogsfing = 'BA99 FE9E 9E74 EBE1 415C  AA0B C0F8 FFB1 2D49 8EC7'

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
#create table blogs(
#blogg_id int(11) not null AUTO_INCREMENT,
#title text not null,
#texten longtext not null,
#vem text not null,
#comment text not null,
#commentedby tinytext not null,
#at_time date not null
#PRIMARY KEY(blogg_id)
#);
# create table comment ( comment_id int(11) not null AUTO_INCREMENT, comment_date date not null, comment text not null, commentedby text not null, PRIMARY KEY (comment_id));

#(
#inside the db
#mysql> show tables;
#+-------------------+
#| Tables_in_bloggen |
#+-------------------+
#| bloggen           |
#| blogs             |
#| comment           |  #didnt need that
#+-------------------+
#3 rows in set (0.00 sec)

#mysql> show columns in bloggen;
#+-----------------+--------------+------+-----+---------+----------------+
#| Field           | Type         | Null | Key | Default | Extra          |
#+-----------------+--------------+------+-----+---------+----------------+
#| user_id         | int(11)      | NO   | PRI | NULL    | auto_increment |
#| name            | varchar(200) | NO   |     | NULL    |                |
#| des             | longtext     | NO   |     | NULL    |                |
#| password        | text         | NO   |     | NULL    |                |
#| pgp             | text         | NO   |     | NULL    |                |
#| pgp_fingerprint | text         | NO   |     | NULL    |                |
#| role            | text         | NO   |     | NULL    |                |
#| joined          | date         | NO   |     | NULL    |                |
#| btcaddress      | text         | NO   |     | NULL    |                |
#| email           | text         | NO   |     | NULL    |                |
#+-----------------+--------------+------+-----+---------+----------------+
#10 rows in set (0.01 sec)

#mysql> show columns in blogs;
#+--------------+----------+------+-----+---------+----------------+
#| Field        | Type     | Null | Key | Default | Extra          |
#+--------------+----------+------+-----+---------+----------------+
#| blogg_id     | int(11)  | NO   | PRI | NULL    | auto_increment |
#| title        | text     | NO   |     | NULL    |                |
#| texten       | longtext | NO   |     | NULL    |                |
#| comment_date | text     | NO   |     | NULL    |                |
#| comment_id   | text     | NO   |     | NULL    |                |
#| comment      | text     | NO   |     | NULL    |                |
#| commentedby  | text     | NO   |     | NULL    |                |
#| vem          | text     | NO   |     | NULL    |                |
#| at_time      | date     | NO   |     | NULL    |                |
#+--------------+----------+------+-----+---------+----------------+
#9 rows in set (0.01 sec)

#mysql> 
#)

#define anonymous role och anti-csrf skyddet
@bloggen.before_request
def csrf_protect():
    if flask.request.method == 'POST':
        token = flask.session.pop('_doda_csrf', None)
        if not token or token != flask.request.form.get('_doda_csrf'):
            return 'error with your request'
#def make_anon():                                #        nope this aint good for now
 #   if 'role' or 'user' or 'admin' not in flask.session:
#	session['role'] = False
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

@bloggen.route('/bloghome')
def bloghome():
    cur = db.cursor()
    cur.execute('select blogg_id, title, texten, vem, at_time from blogs order by blogg_id')
    cul = db.cursor()
    cul.execute('select name from bloggen')
    entries2 = [dict(usr=row[0]) for row in cul.fetchall()]
    entries = [dict(bid=row[0], title=row[1], texten=row[2], vem=row[3], time=row[4]) for row in cur.fetchall()]
    return flask.render_template('blgz.html', entries=entries)

@bloggen.route('/blogg/<blogpostid>', methods=['POST', 'GET'])
def blogposts(blogpostid):
    theid = blogpostid
    cur = db.cursor()
    rr = db.cursor()
    rr.execute('select comment, commentedby, comment_date from blogs where comment_id=%s order by comment_date', (theid,))
    mentries = [dict(comment=row[0], by=row[1], date=row[2]) for row in rr.fetchall()]
    cur.execute('select title, vem, at_time, texten, commentedby, comment from blogs where blogg_id=%s', (theid,))
    #fello = mentries[0]
    entries = [dict(title=row[0], vem=row[1], time=row[2], texten=row[3], by=row[4], comment=row[5]) for row in cur.fetchall()]
    if flask.request.method == 'POST':
	vrll = db.cursor()
	who = flask.request.form['by']
	comment = flask.request.form['comment']
	com = comment.replace('<', '?')
	comment = com
	today = datetime.date.today()
	
	who = who.replace('<', '?')
	vrll.execute('insert into blogs (comment, commentedby, comment_date) values (%s, %s, %s)', (comment, who, today))
	
	
    return flask.render_template('blogpost.html', entries=entries, allentries=mentries)


@bloggen.route('/blogger/<nick>')
def blogger(nick):
    n = nick
    cur = db.cursor()
    cur.execute('select des, joined, btcaddress from bloggen where name=%s', (n,))
    entries = [dict(des=row[0], joined=row[1], btc=row[2]) for row in cur.fetchall()]
    return flask.render_template('blog.html', entries=entries, name=n)

@bloggen.route('/home', methods=['POST', 'GET'])
def user():
    if not flask.session:
	return flask.redirect(flask.url_for('login'))

    if flask.request.method == 'POST':
	blogpost = flask.request.form['blogpost']
	he = blogpost.replace('<', '_') #protect from <scripts>
	blogpost = he
	title = flask.request.form['Title'] 
	nick = flask.escape(flask.session['nick'])
	cur = db.cursor()
	emnick = flask.escape(flask.session['nick'])
	today = datetime.date.today()
	cur.execute('insert into blogs (texten, title, vem, at_time) values (%s, %s, %s, %s)', (blogpost, title, nick, today))
	db.commit()
	cuu = db.cursor()

	t = 'blog post added! check it at /blogg/'
	cuu.execute('select blogg_id from blogs where title=%s', (title,))
	ll = cuu.fetchone()
	AA = str(t) + str(ll[0])
	link = AA
	return flask.render_template('user.html', error=link)  

    
    ff = db.cursor()
    emnick = flask.escape(flask.session['nick'])
    ff.execute('select texten, title from blogs where vem=%s', (emnick,))
    entries = [dict(text=row[0], title=row[1]) for row in ff.fetchall()]
    return flask.render_template('user.html', emnick=emnick, entries=entries)

@bloggen.route('/main/<nick>')
def users(nick):
    if not flask.session:
        return flask.redirect(flask.url_for('login'))
    
    
    return flask.render_template('user.html', emnick = flask.escape(flask.session['nick']),)




#admin panel
@bloggen.route('/admin')
def admin():
    #if flask.session.has_key('role') and flask.session['role'] == 'admin':
    if flask.request.method == 'POST':
	ban = flask.request.form['ban']
	delet = flask.request.form['delete']
	if ban:
	    cur = db.cursor()
	    cur.execute('update bloggen set name=%s where name=%s' ('banneduser', ban))
	    error = 'usr ' + ban + ' have been banned'
	    return flask.render_template('admin.html', error=error)
	if delet:
	    cur = db.cursor()
	    cur.execute('alter table bloggen drop * where name=%s' (ban,))
	    error = 'usr ' + ban + ' have been deleted' 
	    return flask.render_template('admin.html', error=error)
    return flask.render_template('admin.html', error=error)

   # return flask.redirect(flask.url_for('nono'))

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
    
    
    #login
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
	xaa = db.cursor()
	xaa.execute('select pgp_fingerprint from bloggen where name=%s', (nickname,))
	thefing = xaa.fetchone()
	
	if lpgp[0] == 'no':
	    if hashedpasswd == result[0]:
		flask.session['im_online'] = True
		flask.session['nick'] = nickname
		flask.session['role'] = roler[0]
		return flask.redirect(flask.url_for(str(flask.session["role"])))
			
	if thefing:
	    shelloo = base64.b64encode(urandom(16)) #base64 encode bytes from the kernel to use as auth for 2 factor auth code
	    data = str(shelloo)
	    fing = thefing[0]
	    encrypted_ascii_data = gpg.encrypt(data, fing)
	    hello = str(encrypted_ascii_data)
	    #sig2 = gpg.sign(hello, default_key=thefing, passphrase='passwd')
	    sigmsg = hello
	    usrin = flask.request.form['code']
	    if usrin == shelloo:
		flask.session['online'] = True
		flask.session['nick'] = nickname
		flask.session['role'] = roler[0]
		return flask.render_template(flask.url_for(str(flask.session['role'])))
	 #   if flask.request.method == 'POST':
	#	if secret == secdata:
#		    flask.session['im_online'] = True
#		    flask.session['nick'] = nickname
#		    flask.session['role'] = roler[0]
            #return flask.redirect(flask.url_for(str(flask.session["role"])))		    

	    return flask.render_template('2factor.html', user=nickname, thecode=sigmsg, kid=fing)	

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

#pgp test
@bloggen.route('/test', methods=['POST', 'GET'])
def test():
    shelloo = base64.b64encode(urandom(16)) #base64 encode bytes from the kernel to use as auth for 2 factor auth code
    data = str(shelloo)
    thefing = '4F2778BDB03EB510FB2AA7A74BF038498F6112B1'
    encrypted_ascii_data = gpg.encrypt(data, thefing)
    hello = str(encrypted_ascii_data)
    return '' + hello

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
	 #import key
	gpg.import_keys(pgp)
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
#	    pgp_fingerprint = 'no'
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
