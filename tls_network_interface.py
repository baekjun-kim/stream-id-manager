'''
tls_network_interface.py
It is a tls server for managing stream IDs.
'''
import socket
import ssl
import stream_id_manager
import logging
LOCAL_HOST = '10.0.10.1'
LOCAL_PORT = 3100
SIZE = 1024
logging.basicConfig(level=logging.DEBUG)
logging.info('[TLS Server] Import Module')

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='./tls_key/myCrt.crt', keyfile='./tls_key/private_key.pem')

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((LOCAL_HOST, LOCAL_PORT))
server_socket.listen(1)
logging.info('[TLS Server] Server Started at {}:{}'.format(LOCAL_HOST, LOCAL_PORT))

while True:
    client_socket, client_addr = server_socket.accept()
    logging.info('[TLS Server] Client Received: {}'.format(client_addr))

    connstream = context.wrap_socket(client_socket, server_side=True)

    msg = connstream.recv(SIZE)
    logging.debug('[TLS Server] received msg: {}'.format(msg))
    pubkey = stream_id_manager.issue_streamId(msg)
    logging.debug('[TLS Server] Issued Stream ID: {}'.format(pubkey))
    connstream.sendall(pubkey[8:])
    logging.info('[TLS Server] Send message to client')

    connstream.close()
    logging.info('[TLS Server] Close client socket')
