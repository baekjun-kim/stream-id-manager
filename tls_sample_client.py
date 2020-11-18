'''
tls_sample_client.py
To prove working of the TLS server (network_interface.py)
'''
import argparse
import socket
import ssl

host = '127.0.0.1'
port = 3100

def main():
    parser = argparse.ArgumentParser(description="Client to issue a stream ID.")
    parser.add_argument('uid', help='user ID')
    args = parser.parse_args()

    if args.uid:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.load_verify_locations('./tls_key/myCrt.crt')
        s = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        s.connect((host, port))
        s.sendall(args.uid.encode('utf-8'))

        data = s.recv(1024)
        print('RECEIVED: ', data)

        s.close()

if  __name__ == '__main__':
    main()
