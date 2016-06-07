# blogger


this code is copyrighted under 
BEERWARE LICENSE
/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <flipchan(at)riseup.net> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Filip kälebo
 * ----------------------------------------------------------------------------
 */


and free for all to use,copy,hack etc..

install on debian(/debian based os )

pip install -r reqs.txt
apt-get install nginx tor mysql-server 


Mysql code:
create database blogg;
create table bloggen(
user_id int(11) not null AUTO_INCREMENT,
name varchar(200) not null,
des longtext not null,
password text not null,
pgp text not null,
role text not null,
joined date not null,
btcaddress text not null,
email text not null,
PRIMARY KEY(user_id));

if it worked u should be able to:
mysql> show columns in bloggen;
+------------+--------------+------+-----+---------+----------------+
| Field      | Type         | Null | Key | Default | Extra          |
+------------+--------------+------+-----+---------+----------------+
| user_id    | int(11)      | NO   | PRI | NULL    | auto_increment |
| name       | varchar(200) | NO   |     | NULL    |                |
| des        | longtext     | NO   |     | NULL    |                |
| password   | text         | NO   |     | NULL    |                |
| pgp        | text         | NO   |     | NULL    |                |
| role       | text         | NO   |     | NULL    |                |
| joined     | date         | NO   |     | NULL    |                |
| btcaddress | text         | NO   |     | NULL    |                |
| email      | text         | NO   |     | NULL    |                |
+------------+--------------+------+-----+---------+----------------+
9 rows in set (0.10 sec)


run with tor 
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:8080
