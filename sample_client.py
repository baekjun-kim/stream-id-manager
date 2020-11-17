'''
sample_client.py
To prove working of the server (network_interface.py)
'''
import argparse
import socket

host = '127.0.0.1'
ip = 3099

def main():
    parser = argparse.ArgumentParser(description="Client to issue a stream ID.")
    parser.add_argument('uid', help='user ID')
    args = parser.parse_args()

    if args.uid:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, ip))
        s.sendall(args.uid)

        data = s.recv(1024)
        print('RECEIVED: ', data)

        s.close()

if  __name__ == '__main__':
    main()
