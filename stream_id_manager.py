from Crypto.PublicKey import RSA
from hashlib import sha256
import os
from base64 import b64encode
import logging
import argparse
RSA_KEY_LENGTH = 1024
dir_name = 'keys'

def issue_streamId (userId):
    # hash with userId
    m = sha256()
    m.update(userId.encode('UTF-8'))
    userId_digest = m.digest()

    # use - and _ instead of + and / in base64 alphabet, as same as URL safe
    file_name = b64encode(userId_digest, altchars = '-_')

    logging.debug('Input user ID: {}'.format(userId))
    logging.debug('hash digest in base64: {}'.format(file_name))

    pubkey_file_name = 'PUBKEY_' + file_name + '.pem'
    pubkey_file_dir = os.path.join(dir_name, pubkey_file_name)
    prvkey_file_name = 'PRVKEY_' + file_name + '.pem'
    prvkey_file_dir = os.path.join(dir_name, prvkey_file_name)

    if os.path.isfile(pubkey_file_dir):
        logging.debug('RSA key file is already exists')
        f = open(pubkey_file_dir, 'r')
        rsa_key = RSA.importKey(f.read())
        f.close()
        return None

    else:
        logging.debug('RSA key file does not exist')
        rsa_key = RSA.generate(RSA_KEY_LENGTH)
        logging.debug('RSA key generation is done')
        with open(pubkey_file_dir, 'wb') as f:
            f.write(rsa_key.publickey().exportKey('PEM'))
        with open(prvkey_file_dir, 'wb') as f:
            f.write(rsa_key.exportKey('PEM'))
        return None

def reset_database():
    for root, dirs, files in os.walk(dir_name):
        for f in files:
            os.remove(os.path.join(root, f))
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Issue a Stream key.')
    parser.add_argument('-v', '--verbose', help='show debug logs', action='store_true')
    parser.add_argument('uid', help='input user ID');
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    if args.uid:
        issue_streamId(args.uid)
