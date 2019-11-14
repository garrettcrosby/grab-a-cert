#################
# version 3.2.2 #
#################

import sys
import requests
import configparser
import logging
import logging.handlers
import socket
from datetime import datetime, timedelta
from subprocess import call
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from os import path

def login(role, secret, vault_server, ca):
    auth_url = 'https://{0}/v1/auth/approle/login'.format(vault_server)
    payload = '{{"role_id": "{0}", "secret_id": "{1}"}}'.format(role, secret)
    r = requests.post(auth_url, data=payload, verify=ca)
    response = r.json()
    return response['auth']['client_token']

def get_rootCA(vault_server, int_ca, cn, logger):
    request_ca = 'https://{0}/v1/pki/ca/pem'.format(vault_server)
    request_int = 'https://{0}/v1/pki/cert/{1}'.format(vault_server, int_ca)
    r = requests.get(request_ca, verify=False)
    r2 = requests.get(request_int, verify=False)
    #get the int certificate from the server response
    response_json = r2.json()
    int_ca_txt = response_json['data']['certificate']
    root_ca_path = '/etc/pki/ca-trust/source/anchors/privatesharp.crt'
    int_ca_path = '/etc/pki/ca-trust/source/anchors/privatesharp_int.crt'
    try:
        with open(root_ca_path, 'w') as f:
            f.write(r.text)
        with open(int_ca_path, 'w') as f:
            f.write(int_ca_txt)
        call('update-ca-trust')
    except:
        logger.error('failed to install root or int CA on {0}'.format(cn))
        
def grab_cert(vault_server, token, cn, ttl, ca):
    request_url = 'https://{0}/v1/pki_int/issue/privatesharp-dot-com'.format(vault_server)
    data = '{{"common_name": "{0}", "ttl": "{1}"}}'.format(cn, ttl)
    r = requests.post(request_url, headers = {'X-Vault-Token': token}, data=str(data), verify=ca)
    return r.json()

def install_cert(response, cert_path, key_path, cn, logger):
    data = response['data']
    cert = data['certificate']
    key = data['private_key']
    try:
        with open (cert_path, 'w') as f:
            f.write(cert)
        with open (key_path, 'w') as f:
            f.write(key)
        logger.info('cert and key installed on {0}'.format(cn))
    except:
        logger.critical('failed to install cert or key on {0}'.format(cn))

def hook(cmds, logger):
    for cmd in cmds:
        #trim leading space, if present
        if cmd[0] == ' ':
            cmd = cmd[1:]
        try:
            call(cmd, shell=True)
        except:
            logger.error('grabacert could not restart services on {0}'
                         'error with {1}'.format(cn, cmd))

def check_cert(cert_path):
    with open(cert_path, 'r') as f:
        cert = f.read().encode('ascii')
    cert_decode = x509.load_pem_x509_certificate(cert, default_backend())
    now = datetime.now()
    valid_start = cert_decode.not_valid_before
    valid_end = cert_decode.not_valid_after
    validity_time = abs(valid_end - valid_start)
    elapsed_time = abs(now - valid_start)
    if elapsed_time / validity_time > .75:
        return True
    else:
        return False

def main(argv):
    
    if len(argv) > 1:
        print('You suck at life.\n' 
              'You cant even enter args correctly you troglodyte scum.\n'
              'You should rethink your life choices.\n'
              'Really. Get out of here. /RANT OVER\n')
        sys.exit()
    config_file = argv[0]
    #declare variables. These are read from ini file
    Config = configparser.ConfigParser()
    Config.read(config_file)
    vault_server = Config.get('config', 'vault_server')
    int_ca = Config.get('config', 'intermediate_sn')
    cert_path = Config.get('config', 'cert_path')
    key_path = Config.get('config', 'key_path')
    cn = Config.get('config', 'common_name')
    ttl = Config.get('config', 'ttl')
    has_root = Config.get('config', 'has_root')
    cmds = Config.get('config', 'cmd').split(',')
    syslog_server = Config.get('config', 'syslog')
    syslog_port = int(Config.get('config', 'syslog_port'))
    #path to cert bundle on centos, so python will trust vault
    ca = '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
    role = Config.get('config', 'role_id')
    secret = Config.get('config', 'secret_id')

    #set up logging to syslog server
    syslog = logging.getLogger('syslog')
    syslog.setLevel(logging.DEBUG)
    syslog_handler = logging.handlers.SysLogHandler(
                     address=(syslog_server, syslog_port), 
                     socktype=socket.SOCK_DGRAM)
    syslog.addHandler(syslog_handler)
    
    #check for prescence of root_ca, get it if needed
    syslog.info('grabacert is checking for the rootCA on {0}'.format(cn))
    if has_root != 'True':
        syslog.warning('grabacert is installing rootCA on {0}'.format(cn))
        get_rootCA(vault_server, int_ca, cn, syslog)
        Config.set('config', 'has_root', 'True')
        # write updated config values to file
        with open(config_file, 'w') as f:
            Config.write(f)
    
    #now we authenticate to vault server and get a service token
    try:
        token = login(role, secret, vault_server, ca)
        syslog.info('grabacert logged into vault on {0}'.format(cn))
    except:
        syslog.error('grabacert failed to log into vault on {0}'.format(cn))
 
    #check validity of cert
    if path.exists(cert_path):
        syslog.info('grabacert is checking the cert on {0}'.format(cn))
        if check_cert(cert_path) == False:
        #False means the cert has not passed the threshold for a renewal
        #so we will exit
            syslog.info('cert is good on {0}'.format(cn))
            sys.exit()
        else:
        #A return of true means that 75% of the cert's validity period has passed
        #Let's go ahead and grab a new one
            syslog.warning('renewing cert for {0}'.format(cn))
            cert = grab_cert(vault_server, token, cn, ttl, ca)
            install_cert(cert, cert_path, key_path, cn, syslog)
            if cmds[0] != "":
                hook(cmd, syslog)
    else:
        syslog.warning('getting cert for {0}'.format(cn))
        cert = grab_cert(vault_server, token, cn, ttl, ca)
        install_cert(cert, cert_path, key_path, cn, syslog)
        if cmd != "":
            hook(cmd, syslog)

if __name__ == '__main__':
    main(sys.argv[1:])
