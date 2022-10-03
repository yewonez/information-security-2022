# simple ciphercommunicator relay server
# this code shall not be modified, please edit client.py!!!

from random import random
from socket import AddressFamily, AddressInfo, SocketKind, socket
from threading import Thread

from Crypto.Random import get_random_bytes

ENCRYPTION_KEY: bytes = b""
CLIENT_LIST: dict[AddressInfo, socket] = {}


class SocketWorker(Thread):
    def __init__(self, socket: socket, addr: AddressInfo):
        super().__init__()
        self.sock = socket
        self.addr = addr
        CLIENT_LIST[addr] = socket

    def broadcast(self, msg: bytes):
        print(str(self.addr) + ": " + str(msg))

        for (addr, sock) in CLIENT_LIST.items():
            if addr == self.addr:
                continue

            sock.send(msg)

    def run(self):
        self.sock.send(ENCRYPTION_KEY)

        try:
            while True:
                recv_bytes = self.sock.recv(1024)
                self.broadcast(recv_bytes)
        except:
            CLIENT_LIST.pop(self.addr)


def accept_loop(sock: socket):
    while True:
        client, addr = sock.accept()

        print("[*] Accepted a connection from " + str(addr))
        client.send(ENCRYPTION_KEY)

        SocketWorker(client, addr).start()


# generate random aes key for clients
ENCRYPTION_KEY = get_random_bytes(16)
print("[*] Key generated: " + str(ENCRYPTION_KEY))

master_socket = socket(AddressFamily.AF_INET, SocketKind.SOCK_STREAM)
master_socket.bind(('', 24000))
master_socket.listen(1024)

print("[*] Server started on 0.0.0.0:24000")
accept_loop(master_socket)