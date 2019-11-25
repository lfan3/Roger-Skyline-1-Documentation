# Roger-Skyline-1-Documentation

## IP fix config

1. dans vm: bridge
</br>setting the fixed ip addresse: /etc/network/interfaces

auto enp0s3
iface enp0s3 inet static
	address 10.11.11.42  | must to use this not be distributed local ip add
	netmask 255.255.255.253
	gateway 10.11.254.254 | each floor of 42 has his own gateway, this is the 	gateway for the first floor

2. sudo ifconfig eth0 10.0.0.100 netmask 255.255.255.0

3. others commandes
	1. Set Your IP Address
	ifconfig eth0 192.168.1.5 netmask 255.255.255.0 up
	2. Set Your Default Gateway
	route add default gw 192.168.1.1
	3. Set Your DNS Server
	echo "nameserver 1.1.1.1" > /etc/resolv.conf

4. Assuming you have valid addresses for yourself and your gateway (and you have a clear path to the Interweb) you’re all set. Test by pinging someone.
ping google.com

If you’re using an older Linux system, that’s all you have to do. If you’re on a newer system, read on.
Using ip and netplan
You should start learning ip now, since it’s about to become common everywhere.
Since ifconfig is being phased out, it’s time to get used to the new system. By default, Ubuntu 18.04 doesn’t use ifconfig anymore, and instead uses the new commands, ip and netplan.
Show your IP using ip

ip addr show

5. Bring an interface up or down using ip
	- ip link set eth1 up
	- ip link set eth1 down
	- Showing your routing using ip
	- ip route show

6. édition de la configuration de l'interface réseau
	sudo vim /etc/network/interfaces

## SSH

1. /etc/ssh/sshd_config
	changer le port par defaut:
		vim /etc/ssh/sshd_config
		port 22 --> port 2222;
		relancer le serveur ssh
		service sshd restart---pour fedora
		/etc/init.d/ssh restart --pour debiant
	vérifier: netstat -tnplv | grep ssh

2. Keyboard Layout is based on the following parameters XKB parameters, 
	/etc/default/keyboard

3. SSH config depuis virtualbox
	il faut changer la configuration de reseau depuis virtualbox.
	NAT --port forwarding.
	Name: SSH
	Protocol: TCP
	Host IP: 127.0.0.1
	Host Port: 2222
	IP Guest: Empty
	Port Guest:22
	command: ssh user@127.0.0.1 -p 2222
	problemes de firewall: sudo ufw disable. 
	this command shut downed the firewall 

4. send fichier à travers ssh
	copie and send the fichier via ssh:
	sudo scp -P 2222 test.txt fanfan@127.0.0.1:Documents

5. publickey
	ssh-keygen -t rsa
	ssh-copy-id -i ~/.ssh/id_rsa.pub <username>@<ip>
	1)authentification par mot de pass active: give directely the mot de pass
	2)not active:
		ssh login@serveur "echo $(cat ~/.ssh/id_rsa.pub) >> .ssh/authorized_keys"
	lancez: ssh <username>@ip -p <port_numb>

6. everytime when we change something in the sshd_config,
	we also need to restart the service SSH by the command:
		/etc/init.d/ssh restart

## ADD USER et user privilège

adduser new_user
passwd new_user :to change or add passwd

dans le fichier /etc/sudoers, 
add under #user privilege specification
root   ALL=(ALL:ALL):ALL
linfan All = (ALL:ALL):ALL


## UTILITIES
1. sha1sum:
	sha1sum command utilisation --pakage : libdigest-sha-perlls

## FIREWALL IPTABLES

I)
en root ou sudo iptables
-A chain
-D chain rulenum
-I chain rulenum, sinon inserer tout en haut
-R chain rulenum, remplacer
-L lister
-F chain, supprimer
-P chain regle

II)
1)afficher la list ET supprimer un régle
	afficher: iptables -L
	supprimer: iptables -L --line-numbers
		   iptables -D INPUT 1  
2)remettre à défault
	iptables -F
	iptables -X
3)la police par défaut
	iptables -P INPUT ACCEPT/DROP
	iptables -P FORWARD ACCEPT/DROP
	iptables -P OUTPUT ACCEPT/DROP
4)autoriser les trafic déjà établie
	iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
5) Permettre le trafic entrant sur un port spécifique
	iptables -A INPUT -p tcp -i eth0 --dport ssh(22) -j ACCEPT
	iptables -A INPUT -p tcp -i eth0 --sport 80 -j ACCEPT
6) Autoriser le trafic local
 	iptables -I INPUT 2 -i lo -j ACCEPT
7) autoriser le ping (ICMP)
	iptables -A OUTPUT -p icmp -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
	iptable -A INPUT -p icmp -j ACCEPT
8) save the relges:
	sudo -s iptables-save -c
9) persisting the change: to avoid to redefine after reboot
	sudo /sbin/iptables-save
	/* to clean the rules: just delete the rule and save*/
	sudo iptables -F
	sudo /sbin/iptables-save
10) imap2(email)

III) protection contre le DOS
1)iptables -A INPUT -p tcp --syn -m limit --limit 2/s --limit-burst 30 -j ACCEPT | 2 connections par seconde, eviter syn attack
2)iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT | une connection par seconde
3)

IV) PERSISTANT

ANNEX)
tables: raw, mangle, filter, nat
chains:
	raw: prerouting, output
	mangle: prerouting, input,output,forward,postrouting
	nat: prerouting, output, postrouting
	filter: input, output, forward

## package nécessaire pour l'installation

1)apt-get install sudo
2)apt-get install net-tools (ifconfig)

## commands utiles

### partition
GIB vs GB
sudo fdisk -l
df -h

### useful network command
netstat
nslookup 8.8.8.8 42.fr
traceroute	

les options de netstat
1) -i 
2) -uta, -u UDP -t TCP -a tout les états

### GET TO INTERNET COMMAND
wget www.google.com
curl www.google.com

## gestion de package DPKG dpgk
dpkg -l | less
dpkg -l portsentry

## crontab
```
* * * * * ping -d -c 1 8.8.8.8 >> ~/test
crontab -e  dans le root et dans le linfan, ~ ne signifie pas la meme chose.
crontab -l
crontab -r
service crontab restart

sous root, sudo crontab -e :
* 4 * * 1 (apt-get update && apt-get upgrade -y) >> log
@reboot (apt-get update && sudo apt-get upgrade -y) >> log
0 0 * * * (bash/cronwatch.sh)
```
## fail2ban
attack 
python slowloris.py -p 2222 10.11.11.66
remove issu: 
	service fail2ban stop
	rm -r /etc/fail2ban/
	apt-get purge fail2ban
	apt-get install fail2ban
jail sshd
debannir
sudo fail2ban-client set ssh unbanip 10.11.10.21

## email
installer exim4
/var/mail/mail, path des mails que root recois

étant root 
	echo "root to root "   |  mail -s "test"  root@fanserver
étant utilisateur
	echo "utilisateur to root " | mail -s "test" root@fanserver

## rsync
copie local fichier dans le dossier Demo to remote dossier(serveur)
rsync -avh -e 'ssh -p 2222' ./Demo/ fanfan@192.168.1.53:~/monapp

## apache
modifier le directory of index.html
/etc/apache2/apache2.config
/etc/apache2/sites-availables/000-default

ajouter notre site à serveur
path: /home/dev/www/index.html
create a symbolique link: sudo ln -s /home/dev/www /var/www/happybirthday.fr
configuer le ficher 000-default: /var/www
sudo service apache2 reload
create a config fichier for the new site: sudo vim /ent/apache2/sites-availables/001-happybirthday.conf
le content dans le 001-happybirthday.conf:
	<VirtualHost *.80>
		ServerAdmin roger@debiant
		ServerName happybirthday.fr
		DocumentRoot /var/www/happybirthday.fr

		<Directory /var/www/happybirthday.fr>
			Option -Indexes
			AllowOverride All
		</Directory>
	</VirtualHost>
active the configuration file:
	a2ensite 001-happybirthday
	voir le symbolique link: ls sites-enabled/ -l
tester les errors:
	/usr/sbin/apache2ctl configtest
fichier utile, l'error
	/var/log/apache2/...

## ssl certificat
source documentation : linux-france.org ssl autosigne

//generer le clé privé:
openssl genrsa 1024 > serveur.key

// proteger le clé
chmod 400 serveur.key pour proteger

//apartir le cle, créer un fichier de demand de signature de certificat (CSR Certificate Signing Request)
openssl req -new -key serveur.key > serveur.csr // common name = donmaine name

// création de certificat de l'autorité de certification(CA)
openssl genrsa -des3 1024 > ca.key // -des3 permet de creer un mot de pass

// apartir de clé ca, on créer un certificat x509 pour une durée d'un an auto-signé:
openssl req -new -x509 -days 365 -key ca.key > ca.crt // le common name doit etre différent que celui de serveur.crt par exemple: cert_CA

//config default-ssl

## VIM
//insert at the begining of multipleline
:5,15s/^/#
//find and remplace
:%s/search/replace/g
