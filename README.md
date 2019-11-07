# grab-a-cert
Automated certificate generation and renewal for clients from vault server

Grabacert is a small program for automating client operations with vault root ca. It was written specifically to run on centos 7 servers, but is otherwise agnostic.

In this directory you will find 3 files besides this readme. grabacert.py is the code, while the extensionless file is a linux executable built using pyinstaller using grabacert.py and the --onefile option. The other file is the config file, which should be edited to include the specifics for whatever machine and service it is running on.

WHAT IT DOES: For services that require TLS certs, you can automate the fetching and renewal of these certs using this program on the client, and vault as the server. This program will do several things. First, it checks centos's cert store for the privatesharp root and intermediate ca certs. If it doesn't find them, it will request them from the vault server and install them on the machine. It will then check for the prescence of specific certificates on the machine (defined in the config file), and check on their expiration. If more than 75% of the certs life has elapsed, it will request a new cert from the vault server, install it, and optionally restart whatever service the cert is tied to. It also logs to a syslog server to keep you in the loop as to what its going on, as failure to renew a cert could lead to outages.

EXAMPLE USE CASE: Say we have an apache server that we wish to connect to over https. Normally you would need to generate a CSR from the apache server, copy it to the cert authority and get a signed cert, then install it in apache. This can be a process just time consuming enough to make you want to not want to do it. So what admins usually do is have long lasting (1 year or longer) certs so they dont have to go through this process often. Grabacert does all of this for you so even if you forget or don't feel like doing it, grabacert will go through this whole process automatically. Furthermore, since it is automated, there's no reason not to use short lived certs, which are much more secure.

The executable takes one argument, which should be the path to the config file. You can change the name of the config file as you wish, as long as it keeps its ini extention, and you specify the correct path to it. You can also create multiple config files on one server to run it on multiple services. For example, if you had an apache web server, and a database using tls on the same server, you could simply set up two config files (say apache.ini and sql.ini) and call the program twice with each different config as an arguement.

You can set the program up in a privileged crontab. For the previous example your crontab would look like this: @hourly grabacert /etc/grabacert/apache.ini @hourly grabacert /etc/grabacert/sql.ini

In this case the program would run every hour and check on the certs of your apache and database services. Just make sure you give the executable exec permissions- chmod ugo+x And add it to the path if you please.

ABOUT THE CONFIG FILE: The vault_server option is the ip or fqdn of your vault server, including the port. In our case, it is 172.16.50.43:8200

intermediate_sn is the serial number of the intermediate cert authority. The program queries vault for this cert based on its s/n, which is what vault wants. It can find the root without the s/n however.

role_id this is used to authenticate to vault and get a token. I have a role set up in vault specifically for the grabacert app. Basically all it can do is get and renew leaf certs.

secret_id is the password for the role id, if you will.

cert_path is the path/name of the cert that you want to install/renew on the client. When grabacert runs it will check to see if this path exists. If it does not, it will request an new cert and install it to this path. If the path does exist, it will read the cert and check its expiration date.

key_path is the path to the private key of the cert at cert_path

common_name is the common name that will go on the client cert.

ttl is the time to live of the client cert. It will request a cert from vault with this value. Valid examples are: 24h 6h 30m 100d and so on. Recommended ttl is 24h. You can go longer or shorter, but make sure that you set a sensible schedule for the program to run, so you don't end up with your cert lapsing because the program didn't run often enough to check it. Remember that it renews after it crosses a threshold of 75% of cert life elapsed. So for instance, if you set your cert life to one hour and ran this program every thirty minutes, there's good chance you will have issues, as it will only renew it if there is fifteen minutes of life left on it. Again, reccomended ttl is 24h and run the program hourly for good results.

has_root should be set to False when installed, unless you have manually installed the root ca. The program will change this value after it successfully installs the rootca. (it actually doesn't right now due to a bug). In that case you can change it to True and it will skip the root cert check on run.

cmd is any command you want the program to exec after it is finished. Usually you would put a command to restart whatever service you were renewing a cert for, for example systemctl restart apache. This way you ensure that the service you are getting a cert for starts using the renewed cert.

Finally there is syslog and syslog_port, which are what you might expect them to be. The ip of the syslog server you want to log to, and whatever port the syslog server is listening on.
