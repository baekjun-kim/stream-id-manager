'''
network_interface.py
It is a server for manage stream IDs.
'''
import socket
import stream_id_manager
import logging
LOCAL_HOST = '127.0.0.1'
LOCAL_PORT = 3099
SIZE = 1024
logging.basicConfig(level=logging.DEBUG)
logging.info('[Server] Import Module')

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((LOCAL_HOST, LOCAL_PORT))
server_socket.listen(1)
logging.info('[Server] Server Started')

while True:
    client_socket, client_addr = server_socket.accept()
    logging.info('[Server] Client Received: {}'.format(client_addr))

    msg = client_socket.recv(SIZE)
    logging.debug('[Server] received msg: {}'.format(msg))
    pubkey = stream_id_manager.issue_streamId(msg)
    logging.debug('[Server] Issued Stream ID: {}'.format(pubkey))
    client_socket.sendall(pubkey)
    logging.info('[Server] Send message to client')
    
    client_socket.close()
    logging.info('[Server] Close client socket')
