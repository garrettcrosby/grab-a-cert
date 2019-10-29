import Paths
import requests
import ssl
import configparser
from datetime import datetime, timedelta
from subprocess import call
from cryptography import x509

def get_rootCA(vault_server, int_ca):
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
    except Exception as e: print(e)

def grab_cert(vault_server, token, cn, ttl):
    request_url = 'https://{0}/v1/pki_int/issue/privatesharp-dot-com'
    data = '{"common_name": "{0}", "ttl": "{1}"]'.format(cn, ttl)
    r = requests.post(request_url, headers = {'X-Vault-Token': token}, data=data)
    return r.json()

def install_cert(response, cert_path, key_path):
    data = response['data']
    cert = data['certificate']
    key = data['private_key']
    with open (cert_path, 'w') as f:
        f.write(cert)
    with open (key_path, 'w') as f:
        f.write(key)

def hook(cmd):
    call(cmd)

def check_cert(cert_path):
    with open(cert_path, 'r') as f:
        cert = f.read().encode('ascii')
    now = datetime.now()
    valid_start = cert.not_valid_before
    valid_end = cert.not_valid_after
    validity_time = abs(valid_end - valid_start)
    elapsed_time = abs(now - valid_start)
    if elapsed_time / validity_time > .75:
        return True
    else:
        return False

def main():

    #declare variables. These are read from ini file
    Config = configparser.ConfigParser()
    Config.read('config.ini')
    vault_server = Config.get('config', 'vault_server')
    int_ca = Config.get('config', 'intermediate_sn')
    token = Config.get('config', 'token')
    cert_path = Config.get('config', 'cert_path')
    key_path = Config.get('config', 'key_path')
    cn = Config.get('config', 'common_name')
    ttl = Config.get('config', 'ttl')
    has_root = Config.get('config', 'has_root')
    cmd = Config.get('config', 'cmd')

    #check for prescence of root_ca, get it if needed
    if has_root != 'True':
        get_rootCA(vault_server, int_ca)
        Config.set('config', 'has_root', 'True')

    #check validity of cert
    if Path.exists(cert_path):
        if check_cert(cert_path) == False:
        #False means the cert has not passed the threshold for a renewal
        #so we will exit
        exit()
    else:
        #A return of true means that 75% of the cert's validity period has passed
        #Let's go ahead and grab a new one
        cert = grab_cert(vault_server, token, cn, ttl)
        install_cert(cert, cert_path, key_path)
        if cmd != "":
            hook(cmd)

if __name__ == '__main__':
    main()
        
