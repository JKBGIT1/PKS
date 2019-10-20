import socket
import struct
import binascii

hlavickaPreSpravu = 8
hlavickaPreSubor = 8
hlavickaPreSpojenie = 4
hlavickaPreFeedback = 4


def getNazovSuboru(cestaKSuboru):
    nazov = ""
    for i in range(0, len(cestaKSuboru)):
        if cestaKSuboru[i] == '\\' or cestaKSuboru[i] == '/' or cestaKSuboru[i] == ':':
            nazov = cestaKSuboru[i + 1:]
    return nazov


def posliPrvyPacketSubor(clientSocket, clientAddressPort, nazovSuboru, aktualnyPacket):
    checksumSubor = binascii.crc_hqx(nazovSuboru.encode(), 0)
    hlavicka = struct.pack("ccHi", b'4', b'0', checksumSubor, int(aktualnyPacket))
    clientSocket.sendto(hlavicka + nazovSuboru.encode(), clientAddressPort)
    odozvaNazovSuboru = clientSocket.recvfrom(hlavickaPreFeedback)
    (dataType, check, checksum) = struct.unpack("ccH", odozvaNazovSuboru[0][0:hlavickaPreFeedback])
    if int(dataType) == 2 and int(check) == 1 and checksum == binascii.crc_hqx(dataType + check, 0):
        print("Nazov suboru prisiel v poriadku")
    else:
        print("Nazov suboru neprisiel")
        clientSocket.sendto(hlavicka + nazovSuboru.encode(), odozvaNazovSuboru[1])


def posliPacketSubor(packetData, aktualnyPacket):
    checksum = binascii.crc_hqx(packetData, 0)
    hlavicka = struct.pack("ccHi", b'4', b'0', checksum, int(aktualnyPacket))
    bytesToSend = hlavicka + packetData
    return bytesToSend


def posliPoslednyPacketSubor(packetData, aktualnyPacket):
    checksum = binascii.crc_hqx(packetData, 0)
    hlavicka = struct.pack("ccHi", b'4', b'1', checksum, int(aktualnyPacket))
    bytesToSend = hlavicka + packetData
    return bytesToSend


def vytvorSpojenie(clientSocket, clientAddressPort):
    checksumSpojenie = binascii.crc_hqx((b'1' + b'1'), 0)
    hlavicka = struct.pack("ccH", b'1', b'1', checksumSpojenie)
    clientSocket.sendto(hlavicka, clientAddressPort)
    odozvaSpojenie = clientSocket.recvfrom(hlavickaPreSpojenie)
    (dataType, conn, checksum) = struct.unpack("ccH", odozvaSpojenie[0][0:hlavickaPreSpojenie])
    if int(dataType) == 1 and int(conn) == 2 and checksum == binascii.crc_hqx(b'1' + b'2', 0):
        return "ok"
    else:
        return "deny"


def posliPacketSprava(packetSprava, currentPacket):
    checksum = binascii.crc_hqx(packetSprava.encode(), 0)
    hlavicka = struct.pack("ccHi", b'3', b'0', checksum, int(currentPacket))
    bytesToSend = hlavicka + packetSprava.encode()
    return bytesToSend


def posliChybnyPacketSprava(packetSprava, currentPacket):
    checksum = binascii.crc_hqx((packetSprava + "1").encode(), 0)
    hlavicka = struct.pack("ccHi", b'3', b'0', checksum, int (currentPacket))
    bytesToSend = hlavicka + packetSprava.encode()
    return bytesToSend


def posliPoslednyPacketSprava(packetSprava, currentPacket):
    checksum = binascii.crc_hqx(packetSprava.encode(), 0)
    hlavicka = struct.pack("ccHi", b'3', b'1', checksum, int(currentPacket))
    bytesToSend = hlavicka + packetSprava.encode()
    return bytesToSend


def skontrolujFeedback(clientSocket, spravaBajty):
    feedbackBajty = clientSocket.recvfrom(hlavickaPreFeedback)
    (dataType, check, checksumFeedBack) = struct.unpack("ccH", feedbackBajty[0][0:hlavickaPreFeedback])
    if int(dataType) == 2 and int(check) == 1 and checksumFeedBack == binascii.crc_hqx(dataType + check, 0):
        print("Dobry feedback")
    else:
        print("Zly feedback")
        clientSocket.sendto(spravaBajty, feedbackBajty[1])


def skontrolujPacketSpravy(serverSocket ,currentPacket, ocakavanyPacket, checksum, prijateBajty):
    if int(currentPacket) == int(ocakavanyPacket) and checksum == binascii.crc_hqx(prijateBajty[0][hlavickaPreSpravu:], 0):
        checksumFeedBack = binascii.crc_hqx(b'2' + b'1', 0)
        serverSocket.sendto(struct.pack("ccH", b'2', b'1', checksumFeedBack), prijateBajty[1])
        return prijateBajty
    else:
        print("Treba znova poslat packet")
        checksumFeedBack = binascii.crc_hqx(b'2' + b'0', 0)
        serverSocket.sendto(struct.pack("ccH", b'2', b'0', checksumFeedBack), prijateBajty[1])
        noveBajty = serverSocket.recvfrom(1500)
        return noveBajty


def skontrolujPacketSubor(serverSocket, currentPacket, ocakavanyPacket, checksum, prijateBajty):
    if int(currentPacket) == int(ocakavanyPacket) and checksum == binascii.crc_hqx(prijateBajty[0][hlavickaPreSubor:], 0):
        chceksumFeedBack = binascii.crc_hqx(b'2' + b'1', 0)
        serverSocket.sendto(struct.pack("ccH", b'2', b'1', chceksumFeedBack), prijateBajty[1])
        return prijateBajty
    else:
        print("Treba znova poslat packet")
        chceksumFeedBack = binascii.crc_hqx(b'2' + b'0', 0)
        serverSocket.sendto(struct.pack("ccH", b'2', b'0', chceksumFeedBack), prijateBajty[1])
        bajty = serverSocket.recvfrom(1500)
        return bajty


while 1:
    typUzlu = input("Vysielajuci uzol - v, prijimaci - p, koniec - k\n")
    if typUzlu == 'v':
        clientIp = input("Zadaj IP adresu: ")
        clientPort = int(input("Zadaj port: "))
        clientAddressPort = (clientIp, clientPort)
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while 1:
            typDat = input("subor - s, sprava - m, koniec - k\n")
            if typDat == 's':
                checkSpojenie = vytvorSpojenie(clientSocket, clientAddressPort)
                if checkSpojenie == "ok":
                    aktualnyPacket = int(1)
                    cestaKSuboru = input("Zadaj cestu k suboru: ")
                    nazovSuboru = getNazovSuboru(cestaKSuboru)
                    posliPrvyPacketSubor(clientSocket, clientAddressPort, nazovSuboru, aktualnyPacket)
                    aktualnyPacket += 1
                    maxPacketLength = input("Zadaj dlzku max packetu: ")
                    while int(maxPacketLength) > 1500 or int(maxPacketLength) < (hlavickaPreSubor + 1):
                        maxPacketLength = input("Zadaj dlzku max packetu: ")
                    subor = open(cestaKSuboru, "rb")
                    with open(cestaKSuboru, 'rb') as suborhandle:
                        celySubor = suborhandle.read()
                    subor.close()
                    for i in range(0, len(celySubor), int(maxPacketLength) - hlavickaPreSubor):
                        packetData = celySubor[i: i + int(maxPacketLength) - hlavickaPreSubor]
                        if i + int(maxPacketLength) - hlavickaPreSubor >= len(celySubor):
                            dataBajty = posliPoslednyPacketSubor(packetData, aktualnyPacket)
                        else:
                            dataBajty = posliPacketSubor(packetData, aktualnyPacket)
                        clientSocket.sendto(dataBajty, clientAddressPort)
                        skontrolujFeedback(clientSocket, dataBajty)
                        aktualnyPacket += 1
                else:
                    print("Nepodarilo sa vytvorit spojenie s prijimacim uzlom")
            elif typDat == 'm':
                checkSpojenie = vytvorSpojenie(clientSocket, clientAddressPort)
                if checkSpojenie == "ok":
                    aktualnyPacket = 1
                    maxPacketLength = input("Zadaj dlzku max packetu: ")
                    while int(maxPacketLength) > 1500 or int(maxPacketLength) < (hlavickaPreSpravu + 1):
                        maxPacketLength = input("Zadaj dlzku max packetu: ")
                    poslatChybnyPacket = input("Poslat chybny - ano, neposlat chybny - nie\n")
                    sprava = input("Zadaj spravu, ktoru chces poslat: ")
                    for i in range(0, len(sprava), int(maxPacketLength) - hlavickaPreSpravu):
                        packetSprava = sprava[i: i + int(maxPacketLength) - hlavickaPreSpravu]
                        if i + int(maxPacketLength) - hlavickaPreSpravu >= len(sprava):
                            spravaBajty = posliPoslednyPacketSprava(packetSprava, aktualnyPacket)
                        else:
                            if poslatChybnyPacket == "ano":
                                spravaBajty = posliChybnyPacketSprava(packetSprava, aktualnyPacket)
                                poslatChybnyPacket = "nie"
                            else:
                                spravaBajty = posliPacketSprava(packetSprava, aktualnyPacket)
                        clientSocket.sendto(spravaBajty, clientAddressPort)
                        skontrolujFeedback(clientSocket, spravaBajty)
                        aktualnyPacket += 1
                else:
                    print("Nepodarilo sa nadviazat spojenie s prijimacim uzlom")
            elif typDat == 'k':
                clientSocket.close()
                break
    elif typUzlu == 'p':
        celaSprava = ""
        celeData = b''
        prijatySuborCesta = ""
        bufferSize = 1500
        ocakavanyPacket = int(1)
        serverPort = int(input("Zadaj port: "))
        serverAddressPort = ('', serverPort)
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        serverSocket.bind(serverAddressPort)
        print("Prijimaci uzol je pripraveny prijat data")
        while 1:
            prijateBajty = serverSocket.recvfrom(bufferSize)
            dataType = chr(prijateBajty[0][0])
            if dataType == '1': # Toto je na connection
                (dataType, conn, checksum) = struct.unpack("ccH", prijateBajty[0][0:hlavickaPreSpojenie])
                if int(conn) == 1 and checksum == binascii.crc_hqx(b'1' + b'1', 0):
                    checksumOdozvaSpojenie = binascii.crc_hqx(b'1' + b'2', 0)
                    serverSocket.sendto(struct.pack("ccH", b'1', b'2', checksumOdozvaSpojenie), prijateBajty[1])
                else:
                    print("Nespravne spojenie")
            elif dataType == '2': # Toto je na feedback
                print("Zatedy nic")
            elif dataType == '3': # Toto je sprava
                (dataType, end, checksum, currentPacket) = struct.unpack("ccHi", prijateBajty[0][0:hlavickaPreSpravu])
                noveBajty = skontrolujPacketSpravy(serverSocket, currentPacket, ocakavanyPacket, checksum, prijateBajty)
                (dataType, end, checksum, currentPacket) = struct.unpack("ccHi", noveBajty[0][0:hlavickaPreSpravu])
                celaSprava += noveBajty[0][hlavickaPreSpravu:].decode("utf-8")
                if (int(end) == 1):
                    odosielatel =  "Client IP Address: {}".format(noveBajty[1])
                    print(odosielatel)
                    print("Pocet packetov: " + str(ocakavanyPacket))
                    print("Sprava: " + celaSprava)
                    ocakavanyPacket = 0
                    celaSprava = ""
                ocakavanyPacket += 1
            elif dataType == '4': # Toto je subor
                (dataType, end, chceksum, currentPacket) = struct.unpack("ccHi", prijateBajty[0][0:hlavickaPreSubor])
                noveBajty = skontrolujPacketSubor(serverSocket, currentPacket, ocakavanyPacket, chceksum, prijateBajty)
                (dataType, end, checksum, currentPacket) = struct.unpack("ccHi", noveBajty[0][0:hlavickaPreSubor])
                if int(currentPacket) == 1:
                    prijatySuborCesta += "C:\\" + noveBajty[0][hlavickaPreSubor:].decode("utf-8")
                if int(currentPacket) != 1:
                    celeData += noveBajty[0][hlavickaPreSubor:]
                if (int(end) == 1 and currentPacket != 1):
                    print("Pocet packetov: " + str(ocakavanyPacket))
                    newFile = open(prijatySuborCesta, "wb")
                    newFile.write(celeData)
                    ocakavanyPacket = 0
                    celeData = b''
                ocakavanyPacket += 1
            elif dataType == '5': # Toto je keepalive
                print("Zatedy nic")
            elif dataType == '6': # Toto je na ukoncenie spojenia
                print("Zatedy nic")
        serverSocket.close()
    elif typUzlu == 'k':
        print("koniec")
        break
# msgFromServer = "Hello UDP Client"
# bytesToSend = str.encode(msgFromServer)
#
# localIP = input("Enter IP of server: ")  # example "127.0.0.1"
# localPort = int(input("Enter port of server: "))  # example 20001
# bufferSize = int(input("Enter max value, which you can send: "))
# # Create a datagram socket
# UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# # Bind to address and ip
# UDPServerSocket.bind((localIP, localPort))
# print("UDP server up and listening")
#
# # Listen for incoming datagram
# fullMessage = b''
# while True:
#     # Message is stored in this variable, but it has bytes format
#     bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
#     # If message is "koniec", then the server is shut down
#     #if bytesAddressPair[0].decode("utf-8") == "koniec":
#     #    break
#     dataVariable = pickle.loads(bytesAddressPair)
#     # Unpickled the packet
#     # recievedPacket = pickle.loads(bytesAddressPair)
#     # print(recievedPacket)
#     print(dataVariable)
#     '''
#     print(recievedPacket[2])
#     message = bytesAddressPair[0].decode("utf-8")
#     address = bytesAddressPair[1]
#     clientMsg = "Message from client: " + message
#     clientIP = "Client IP Address: {}".format(address)
#     print(clientMsg)
#     print(clientIP)
#     '''
#     # Sending a reply to client
#     # UDPServerSocket.sendto(bytesToSend, address)
#
# UDPServerSocket.close()
