'''
network_interface.py
It is a server for managing stream IDs.
'''
import socket
import stream_id_manager
import logging
import time
from base64 import b64decode
LOCAL_HOST = '10.0.10.1'
LOCAL_PORT = 3099
SIZE = 1024
ENCRYPTED_MESSAGE_SIZE = 172
PUBKEY_SIZE = 204

logging.basicConfig(level=logging.DEBUG)
logging.info('[Server] Import Module')

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((LOCAL_HOST, LOCAL_PORT))
server_socket.listen(1)
logging.info('[Server] Server Started at {}:{}'.format(LOCAL_HOST, LOCAL_PORT))

while True:
    client_socket, client_addr = server_socket.accept()
    logging.info('[Server] Client Received: {}'.format(client_addr))

    msg = client_socket.recv(SIZE)
    logging.debug('[Server] received msg: {}'.format(msg))
    #extract
    public_key = msg[:PUBKEY_SIZE]
    encrypted_message = msg[PUBKEY_SIZE:PUBKEY_SIZE+ENCRYPTED_MESSAGE_SIZE]

    original_message =stream_id_manager.decrypt_message(\
            public_key,\
            b64decode(encrypted_message)).split(':')
    if (stream_id_manager.check_idpw(original_message[0], original_message[1])):
        client_socket.sendall('success')
        logging.info('[Server] Success')
    else:
        client_socket.sendall('fail')
        logging.info('[Server] Failed')
    logging.info('[Server] Send message to client')
    time.sleep(1)
    client_socket.close()
    logging.info('[Server] Close client socket')
