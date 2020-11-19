'''
stream_Id_manager.py
It issue a stream ID for input user ID.

When issue_streamId is called,
If the key files already exist, it reads and returns the public key as OpenSSH format.
Else, it generates RSA key and saves the keys as .pem file in /keys directory.
'''

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha256
import os
from base64 import b64encode
import logging
import argparse
import time
RSA_KEY_LENGTH = 1024
dir_name = 'keys'
idpw_table_name = 'idpw_table'

def idpw_digest (input_ID, input_passwd):
    m = sha256()
    m.update(input_ID.encode('utf-8'))
    m.update(':'.encode('utf-8'))
    m.update(input_passwd.encode('utf-8'))

    # use - and _ instead of + and / in base64 alphabet, as same as URL safe
    return b64encode(m.digest(), altchars='-_')

def issue_streamId (input_ID, input_passwd):
    # hash with ID and password, then encode with base64
    file_name = idpw_digest(input_ID, input_passwd)

    logging.debug('[SIM] Input user ID: {}'.format(input_ID))
    logging.debug('[SIM] Input password: {}'.format(input_passwd))
    logging.debug('[SIM] Hash digest in base64: {}'.format(file_name))

    pubkey_file_name = 'PUBKEY_' + file_name + '.pem'
    pubkey_file_dir = os.path.join(dir_name, pubkey_file_name)
    prvkey_file_name = 'PRVKEY_' + file_name + '.pem'
    prvkey_file_dir = os.path.join(dir_name, prvkey_file_name)

    if os.path.isfile(pubkey_file_dir):
        logging.debug('[SIM] RSA key file already exists')
        f = open(pubkey_file_dir, 'r')
        rsa_key = RSA.importKey(f.read())
        logging.debug('[SIM] RSA key file read complete')
        f.close()
        return rsa_key.exportKey(format = 'OpenSSH')

    else:
        logging.debug('[SIM] RSA key file does not exist')
        tmptime = time.time()
        rsa_key = RSA.generate(RSA_KEY_LENGTH)
        logging.debug('[SIM] RSA key generation is done in {} ms'.\
                format((time.time()-tmptime)*1000))

        #pem file write
        with open(pubkey_file_dir, 'wb') as f:
            f.write(rsa_key.publickey().exportKey('PEM'))
        with open(prvkey_file_dir, 'wb') as f:
            f.write(rsa_key.exportKey('PEM'))

        #idpw table write
        #format: ID PW PUBKEY
        #PUBKEY is OpenSSH format without header
        with open(idpw_table_name, 'a') as f:
            f.write(input_ID + ' ' + input_passwd + ' ' +\
                    rsa_key.publickey().exportKey('OpenSSH')[8:] + ' \n')
            logging.debug('[SIM] ID-PW table addition complete')
        return rsa_key.publickey().exportKey('OpenSSH')

def decrypt_message (input_pubkey, message):
    with open(idpw_table_name, 'r') as f:
        logging.debug('[SIM] ID-PW table open')
        for l in f.readlines():
            component = l.split(' ')
            if component[2] == input_pubkey:
                logging.debug('[SIM] found match public key')
                with open(os.path.join(dir_name,\
                        'PRVKEY_' +idpw_digest(component[0], component[1]) + '.pem')) as prvkey_file:
                    logging.debug('[SIM] open prviate key')
                    rsa_private_key = RSA.importKey(prvkey_file.read())
                    logging.debug('[SIM] load private key success')
                    cipher = PKCS1_OAEP.new(rsa_private_key)
                    return cipher.decrypt(message)
        logging.debug('[SIM] Failed to find public key')
        return None

def check_idpw (input_id, input_pw, input_public_key):
    logging.debug('[SIM] Check ID/PW/PUBKEY')
    with open(idpw_table_name, 'r') as f:
        logging.debug('[SIM] Read ID-PW table')
        for l in f.readlines():
            if (input_id + ' ' + input_pw + ' ' + input_public_key) in l:
                logging.debug('[SIM] Match success')
                return True
        logging.debug('[SIM] Match failed')
    return False

def reset_database():
    #keys
    for root, dirs, files in os.walk(dir_name):
        for f in files:
            os.remove(os.path.join(root, f))

    #id-pw table
    os.remove(idpw_table_name)
    f = open(idpw_table_name, "w")
    f.close()
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Issue a Stream ID.')
    parser.add_argument('-v', '--verbose', help='show debug logs', action='store_true')
    parser.add_argument('ID', help='input ID');
    parser.add_argument('password', help='input password')

    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    if args.ID and args.password:
        pubkey = issue_streamId(args.ID, args.password)
        logging.info('[SIM] Issuing a stream ID is done')
        logging.debug('[SIM] Pubkey: {}'.format(pubkey))

        '''
        print('simple my test start')
        tmpkey = RSA.importKey(pubkey)
        cipher = PKCS1_v1_5.new(tmpkey)
        message = "Hello world"
        enc_message = cipher.encrypt(message.encode('utf-8'))
        print(type(enc_message))
        print('Decrypted message is {}'.format(decrypt_message(pubkey[8:], enc_message)))
        print('Id-pw can match?', check_idpw (args.ID, args.password))
        '''
