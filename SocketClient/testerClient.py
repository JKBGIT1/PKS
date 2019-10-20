import socket
import time
import threading


class KeepAlive(threading.Thread):


    def __init__(self, clientSocket, clientAddressPort):
        super().__init__()
        self.clientSocket = clientSocket
        self.clientAddressPort = clientAddressPort

    def run(self):
        while True:
            if pokracuj == "ano":
                self.clientSocket.sendto("ano".encode(), self.clientAddressPort)
                odozvaKeepAlive = self.clientSocket.recvfrom(3)
                if odozvaKeepAlive[0].decode("utf-8") == "ano":
                    print("Spojenie stale funguje")
                time.sleep(5)


clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
clientAddressPort = ("127.0.0.1", 1245)
keepAlive = KeepAlive(clientSocket, clientAddressPort)
pokracuj = "ano"
keepAlive.start()
while True:
    prejdiSem = input("Chod do podmienky ano/nie\n")
    if prejdiSem == "ano":
        pokracuj = "nie"
    else:
        pokracuj = "ano"