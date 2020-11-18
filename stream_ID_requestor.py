'''
stream_ID_requestor.py
It requests stream ID to stream-key-manager with user ID.
In details, stream_ID_requestor requests stream ID to tls_network_interface.py.
'''
import argparse
import socket
import ssl
import logging

HOST = '10.0.10.1'
PORT = 3100
logging.basicConfig(level=logging.DEBUG)

def main():
    parser = argparse.ArgumentParser(description="Client to issue a stream ID.")
    parser.add_argument('uid', help='user ID')
    args = parser.parse_args()

    if args.uid:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.load_verify_locations('./tls_key/myCrt.crt')
        logging.debug('load CA complete')

        s = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        s.connect((HOST, PORT))
        logging.info('Connect to {}:{}'.format(HOST,PORT))
        s.sendall(args.uid.encode('utf-8'))

        data = s.recv(1024)
        if len(data) != 204:
            logging.error('Insufficient data recieved')
            return None
        logging.info('Recieved Stream ID: {}'.format(data))
        with open('streamID.txt', 'w') as f:
            f.write(data)
        s.close()

if  __name__ == '__main__':
    main()
