import socket
import struct
import threading

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverAddressPort = ("", 1245)
serverSocket.bind(serverAddressPort)
while True:
    prijateBajty = serverSocket.recvfrom(4)
    if prijateBajty[0].decode("utf-8") == "ano":
        print("Prisiel keepalive")
        serverSocket.sendto("ano".encode(), prijateBajty[1])