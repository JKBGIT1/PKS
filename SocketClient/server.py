import socket
import struct
import binascii
import math
import os
import threading
import time

HLAVICKA_UPD = 8
HLAVICKA_IPV4 = 20
HLAVICKA_SPOJENIE = 12 # "cHcci" zaokruhli na 12 aj ked je to 9 bajtov
HLAVICKA_SKONCI_SPOJENIE = 4 # "cH" zaokruhli na 4 bajty, aj ked su to 3
HLAVICKA_KEEPALIVE = 4 # "cH" zaokruhli na 4 bajty, aj ked su to 3
HLAVICKA_SUBOR = 8 # "cHi" 8 bajtov
HLAVICKA_SPRAVA = 8 # "cHi" zaokruhli na 8 bajtov, aj ked je to 7 bajtov
HLAVICKA_FEEDBACK = 12 # "cHci" 4 bajty, po nich bude poslany string velkosti 10, ktory bude drzat hodnoty prijatych suborov
BUFFER_SIZE = 1500 # pouzivam na prijimanie dat
MAX_LENGTH_PACKET = 1472 # pouzivam, ked pytam dlzku od pouzivatela, odpocital som od 1500 udp a ip hlavicku


class KeepAlive(threading.Thread):


    def __init__(self, clientSocket, clientAddressPort):
        super().__init__()
        self.clientSocket = clientSocket
        self.clientAddressPort = clientAddressPort

    def run(self):
        global bolPoslanySubor
        while True:
            if bolPoslanySubor == "ano":
                keepAliveChecksum = binascii.crc_hqx(b'5' + b'0', 0)
                keepAliveHlavicka = struct.pack("cH", b'5', keepAliveChecksum)
                self.clientSocket.sendto(keepAliveHlavicka, self.clientAddressPort)
                odozvaKeepAlive = self.clientSocket.recvfrom(HLAVICKA_KEEPALIVE)
                (dataType, checksum) = struct.unpack("cH", odozvaKeepAlive[0][0:HLAVICKA_KEEPALIVE])
                if int(dataType) == 5 and checksum == binascii.crc_hqx(b'5' + b'0', 0):
                    print("Spojenie stale funguje")
                else:
                    print("Spatny feedback na keepalive")
                    bolPoslanySubor = "nie"
                time.sleep(20)


def posliKeepAliveOdozvu(serverSocket, prijateBajty):
    odozvaKeepAliveChecksum = binascii.crc_hqx(b'5' + b'0', 0)
    odozvaKeepAliveHlavicka = struct.pack("cH", b'5', odozvaKeepAliveChecksum)
    serverSocket.sendto(odozvaKeepAliveHlavicka, prijateBajty[1])


def posliKeepAliveZluOdozvu(serverSocket, prijateBajty):
    odozvaKeepAliveZlyChecksum = binascii.crc_hqx(b'0' + b'0', 0)
    odozvaKeepAliveZlaHlavicka = struct.pack("cH", b'0', odozvaKeepAliveZlyChecksum)
    serverSocket.sendto(odozvaKeepAliveZlaHlavicka, prijateBajty[1])


def getNazovSuboru(cestaKSuboru):
    nazov = ""
    for i in range(0, len(cestaKSuboru)):
        if cestaKSuboru[i] == '\\' or cestaKSuboru[i] == '/' or cestaKSuboru[i] == ':':
            nazov = cestaKSuboru[i + 1:]
    return nazov


def nacitajMaxDlzkuPacketuSubor():
    maxDlzkaPacketu = int(input("Zadaj dlzku packetu od 9 po 1472: "))
    while maxDlzkaPacketu > MAX_LENGTH_PACKET and maxDlzkaPacketu > HLAVICKA_SUBOR:
        maxDlzkaPacketu = int(input("Zadaj dlzku packetu od 9 po 1472: "))
    return maxDlzkaPacketu


def nacitajMaxDlzkuPacketuSprava():
    maxDlzkaPacketu = int(input("Zadaj dlzku packetu od 9 po 1472: "))
    while maxDlzkaPacketu > MAX_LENGTH_PACKET and maxDlzkaPacketu > HLAVICKA_SPRAVA:
        maxDlzkaPacketu = int(input("Zadaj dlzku packetu od 9 po 1472: "))
    return maxDlzkaPacketu


def nacitajBajtyZoSuboru(cestaKSuboru):
    with open(cestaKSuboru, "rb") as handler:
        celySuborBajty = handler.read()
    return celySuborBajty


def skonciSpojenie(clientSocket, clientAddressPort):
    skonciSpojenieChecksum = binascii.crc_hqx(b'6' + b'0', 0)
    hlavickaSkonciSpojenie = struct.pack("cH", b'6', skonciSpojenieChecksum)
    clientSocket.sendto(hlavickaSkonciSpojenie, clientAddressPort)


def spojenieSubor(clientSocket, clientAddressPort, pocetPacketov, nazovSuboru):
    checksumSpojenieSubor = binascii.crc_hqx(b'1' + b'0' + b'1' + b'4' + bytes(pocetPacketov) + nazovSuboru.encode(), 0)
    hlavickaSpojenieSubor = struct.pack("cHcci", b'1', checksumSpojenieSubor, b'1', b'4', int(pocetPacketov)) # dataType, conn, msgOrFile, packetNum, checksum
    clientSocket.sendto(hlavickaSpojenieSubor + nazovSuboru.encode(), clientAddressPort)
    spojenieBajtySubor = clientSocket.recvfrom(HLAVICKA_SPOJENIE)
    (dataType, checksum, conn, msgOrFile, packetNum) = struct.unpack("cHcci", spojenieBajtySubor[0][0:HLAVICKA_SPOJENIE])
    if int(dataType) == 1 and int(conn) == 2 and int(msgOrFile) == 4 and packetNum == int(pocetPacketov) and checksum == binascii.crc_hqx(b'1' + b'0' + b'2' + b'4' + bytes(packetNum), 0):
        return "ok"
    else:
        return "problem"


def spojenieSprava(clientSocket, clientAddressPort, pocetPacketov):
    checksumSpojenieSprava = binascii.crc_hqx(b'1' + b'0' + b'1' + b'3' + bytes(pocetPacketov), 0)
    hlavickaSpojenieSprava = struct.pack("cHcci", b'1', checksumSpojenieSprava, b'1', b'3', int(pocetPacketov))
    clientSocket.sendto(hlavickaSpojenieSprava, clientAddressPort)
    spojenieBajtySprava = clientSocket.recvfrom(HLAVICKA_SPOJENIE)
    (dataType, checksum, conn, msgOrFile, packetNum) = struct.unpack("cHcci", spojenieBajtySprava[0][0:HLAVICKA_SPOJENIE])
    if int(dataType) == 1 and int(conn) == 2 and int(msgOrFile) == 3 and packetNum == int(pocetPacketov) and checksum == binascii.crc_hqx(b'1' + b'0' + b'2' + b'3' + bytes(packetNum), 0):
        return "ok"
    else:
        return "problem"


def posliPacketSprava(clientSocket, clientAddressPort, sprava, aktualnyPacket):
    checksumSprava = binascii.crc_hqx(b'3' + b'0' + bytes(aktualnyPacket) + sprava.encode(), 0)
    hlavickaSprava = struct.pack("cHi", b'3', checksumSprava, int(aktualnyPacket))
    clientSocket.sendto(hlavickaSprava + sprava.encode(), clientAddressPort)


def posliChybnyPacketSprava(clientSocket, clientAddressPort, sprava, aktualnyPacket):
    checksumSpravaChybny = binascii.crc_hqx(b'4' + b'0' + bytes(aktualnyPacket) + sprava.encode(), 0)
    hlavickaSprava = struct.pack("cHi", b'3', checksumSpravaChybny, int(aktualnyPacket))
    clientSocket.sendto(hlavickaSprava + sprava.encode(), clientAddressPort)


def posliPacketSubor(clientSocket, clientAddressPort, data, aktualnyPacket):
    checksumSubor = binascii.crc_hqx(b'4' + b'0' + bytes(aktualnyPacket) + data, 0)
    hlavickaSubor = struct.pack("cHi", b'4', checksumSubor, int(aktualnyPacket))
    clientSocket.sendto(hlavickaSubor + data, clientAddressPort)


def posliChybnyPacketSubor(clientSocket, clientAddressPort, data, aktualnyPacket):
    checksumSuborChybny = binascii.crc_hqx(b'3' + b'0' + bytes(aktualnyPacket) + data, 0)
    hlavickaSubor = struct.pack("cHi", b'4', checksumSuborChybny, int(aktualnyPacket))
    clientSocket.sendto(hlavickaSubor + data, clientAddressPort)


def skontrolujFeedbackSprava(clientSocket, clientAddressPort, bufferOfMessages, aktualnyPacket):
    feedbackBajty = b''
    clientSocket.settimeout(0.1)
    try:
        feedbackBajty = clientSocket.recvfrom(HLAVICKA_FEEDBACK)
    except:
        print("Neposlal sa posledny packet z patice")
        resendPoslednyPacket5checksum = binascii.crc_hqx(b'3' + b'0' + bytes(aktualnyPacket) + bufferOfMessages[9].encode(), 0)
        hlavickaResendPosledny5 = struct.pack("cHi", b'3', resendPoslednyPacket5checksum, int(aktualnyPacket))
        clientSocket.sendto(hlavickaResendPosledny5 + bufferOfMessages[9].encode(), clientAddressPort)
    clientSocket.settimeout(None)
    if (feedbackBajty == b''):
        feedbackBajty = clientSocket.recvfrom(HLAVICKA_FEEDBACK)
    (dataType, checksum, check, firstBadPacket) = struct.unpack("cHci", feedbackBajty[0][0:HLAVICKA_FEEDBACK])
    if int(dataType) == 2 and int(check) == 1 and checksum == binascii.crc_hqx(b'2' + b'0' + b'1' + bytes(firstBadPacket), 0):
        print("Vsetkych packety prisli v pohode.")
    else:
        print("Niektory packet neprisiel alebo nastali problemy")
        prvyZly = int(firstBadPacket)
        while prvyZly <= aktualnyPacket:
            resendSpravaChecksum = binascii.crc_hqx(b'3' + b'0' + bytes(prvyZly) + bufferOfMessages[prvyZly % 10 - 1].encode(), 0)
            resendSpravaHlavicka = struct.pack("cHi", b'3', resendSpravaChecksum, int(prvyZly))
            clientSocket.sendto(resendSpravaHlavicka + bufferOfMessages[prvyZly % 10 - 1].encode(), clientAddressPort)
            prvyZly += 1
        return


def skontrolujFeedbackSubor(clientSocket, clientAddressPort, bufferOfData, aktualnyPacket):
    feedbackBajty = b''
    clientSocket.settimeout(0.1)
    try:
        feedbackBajty = clientSocket.recvfrom(HLAVICKA_FEEDBACK)
    except:
        print("Neposlal sa posledny packet z patice")
        resendPoslednyPacket5checksum = binascii.crc_hqx(b'4' + b'0' + bytes(aktualnyPacket) + bufferOfData[9], 0) # menil som tu veci
        hlavickaResendPosledny5 = struct.pack("cHi", b'4', resendPoslednyPacket5checksum, int(aktualnyPacket))
        clientSocket.sendto(hlavickaResendPosledny5 + bufferOfData[9], clientAddressPort)
    clientSocket.settimeout(None)
    if (feedbackBajty == b''):
        feedbackBajty = clientSocket.recvfrom(HLAVICKA_FEEDBACK)
    (dataType, checksum, check, firstBadPacket) = struct.unpack("cHci", feedbackBajty[0][0:HLAVICKA_FEEDBACK])
    if int(dataType) == 2 and int(check) == 1 and checksum == binascii.crc_hqx(b'2' + b'0' + b'1' + bytes(firstBadPacket), 0):
        print("Vsetkych packety prisli v pohode.")
    else:
        print("Niektory packet neprisiel alebo nastali problemy")
        prvyZly = int(firstBadPacket)
        while prvyZly <= aktualnyPacket:
            resendSuborChecksum = binascii.crc_hqx(b'4' + b'0' + bytes(prvyZly) + bufferOfData[prvyZly % 10 - 1], 0)
            resendSuborHlavicka = struct.pack("cHi", b'4', resendSuborChecksum, int(prvyZly))
            clientSocket.sendto(resendSuborHlavicka + bufferOfData[prvyZly % 10 - 1], clientAddressPort)
            prvyZly += 1
        return


def odozvaSpojenieSprava(serverSocket, prijateBajty, numPacket):
    odozvaSpojenieSpravaChecksum = binascii.crc_hqx(b'1' + b'0' + b'2' + b'3' + bytes(numPacket), 0)
    odozvaSpojenieSpravaHlavicka = struct.pack("cHcci", b'1', odozvaSpojenieSpravaChecksum, b'2', b'3', int(numPacket))
    serverSocket.sendto(odozvaSpojenieSpravaHlavicka, prijateBajty[1])


def odozvaSpojenieSubor(serverSocket, prijateBajty, numPacket):
    odozvaSpojenieSuborChecksum = binascii.crc_hqx(b'1' + b'0' + b'2' + b'4' + bytes(numPacket), 0)
    odozvaSpojenieSuborHlavicka = struct.pack("cHcci", b'1', odozvaSpojenieSuborChecksum, b'2', b'4', int(numPacket))
    serverSocket.sendto(odozvaSpojenieSuborHlavicka, prijateBajty[1])


def odozvaZleSpojenie(serverSocket, prijateBajty):
    zleSpojenieChecksum = binascii.crc_hqx(b'0' + b'0' + b'0' + b'0' + b'0', 0)
    zleSpojenieHlavicka = struct.pack("cHcci", b'0', zleSpojenieChecksum, b'0', b'0', b'0')
    serverSocket.sendto(zleSpojenieHlavicka, prijateBajty[1])


def posliFeedbackSprava(serverSocket, prijateBajty, celaSprava, prvyZlyPacket):
    if int(prvyZlyPacket) == 0:
        print("Packety prisli v pohode")
        feedbackSpravaChecksum = binascii.crc_hqx(b'2' + b'0' + b'1' + bytes(prvyZlyPacket), 0)
        feedbackSpravaHlavicka = struct.pack("cHci", b'2', feedbackSpravaChecksum, b'1', int(prvyZlyPacket))
        serverSocket.sendto(feedbackSpravaHlavicka, prijateBajty[1])
        return celaSprava
    else:
        print("Preposielanie")
        feedbackSpravaChecksum = binascii.crc_hqx(b'2' + b'0' + b'0' + bytes(prvyZlyPacket), 0)
        feedbackSpravaHlavicka = struct.pack("cHci", b'2', feedbackSpravaChecksum, b'0', int(prvyZlyPacket))
        serverSocket.sendto(feedbackSpravaHlavicka, prijateBajty[1])
        while True:
            resendBajty = serverSocket.recvfrom(BUFFER_SIZE)
            (dataType, checksum, currentPacket) = struct.unpack("cHi", resendBajty[0][0:HLAVICKA_SPRAVA])
            if int(dataType) == 3 and int(prvyZlyPacket) == currentPacket and checksum == binascii.crc_hqx(b'3' + b'0' + bytes(currentPacket) + resendBajty[0][HLAVICKA_SPRAVA:], 0):
                celaSprava += resendBajty[0][HLAVICKA_SPRAVA:].decode("utf-8")
                print("Cislo packetu: " + str(currentPacket))
                print("Velkost packetu:", len(resendBajty[0]))
            else:
                print("Problem pri znovu posielani packetov")
            if int(prvyZlyPacket) % 10 == 0 or int(prvyZlyPacket) == int(numPacket):
                return celaSprava
            prvyZlyPacket += 1


def posliFeedbackSubor(serverSocket, prijateBajty, celeData, prvyZlyPacket):
    if int(prvyZlyPacket) == 0:
        print("Packety prisli v pohode")
        feedbackSpravaChecksum = binascii.crc_hqx(b'2' + b'0' + b'1' + bytes(prvyZlyPacket), 0)
        feedbackSpravaHlavicka = struct.pack("cHci", b'2', feedbackSpravaChecksum, b'1', int(prvyZlyPacket))
        serverSocket.sendto(feedbackSpravaHlavicka, prijateBajty[1])
        return celeData
    else:
        print("Preposielanie")
        feedbackSpravaChecksum = binascii.crc_hqx(b'2' + b'0' + b'0' + bytes(prvyZlyPacket), 0)
        feedbackSpravaHlavicka = struct.pack("cHci", b'2', feedbackSpravaChecksum, b'0', int(prvyZlyPacket))
        serverSocket.sendto(feedbackSpravaHlavicka, prijateBajty[1])
        while True:
            resendBajty = serverSocket.recvfrom(BUFFER_SIZE)
            (dataType, checksum, currentPacket) = struct.unpack("cHi", resendBajty[0][0:HLAVICKA_SUBOR])
            if int(dataType) == 4 and int(prvyZlyPacket) == currentPacket and checksum == binascii.crc_hqx(b'4' + b'0' + bytes(currentPacket) + resendBajty[0][HLAVICKA_SUBOR:], 0):
                celeData += resendBajty[0][HLAVICKA_SUBOR:]
                print("Cislo packetu: " + str(currentPacket))
                print("Velkost packetu:", len(resendBajty[0]))
            else:
                print("Problem pri znovu posielani packetov")
            if int(prvyZlyPacket) % 10 == 0 or int(prvyZlyPacket) == int(numPacket):
                return celeData
            prvyZlyPacket += 1


while True:
    typUzlu = input("Vysielajuci - v\nPrijimaci - p\nKoniec -k\n")
    if typUzlu == 'v':
        bolPoslanySubor = "nie"
        clientIp = input("Zadaj IP: ")
        clientPort = input("Zadaj Port: ")
        clientAddressPort = (clientIp, int(clientPort))
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        keepAlive = KeepAlive(clientSocket, clientAddressPort)
        keepAlive.start()
        while True:
            typOperacie = input("Posli subor - s\nPosli spravu - m\nSkonci spojenie - k\n")
            if typOperacie == 's':
                bolPoslanySubor = "nie"
                aktualnyPacket = int(1)
                cestaKSuboru = input("Zadaj cestu k suboru: ")
                nazovSuboru = getNazovSuboru(cestaKSuboru)
                maxDlzkaPacketu = nacitajMaxDlzkuPacketuSubor()
                poslatChybnyPacket = input("Chces poslat chybny packet ano/nie: ")
                celySuborBajty = nacitajBajtyZoSuboru(cestaKSuboru)
                pocetPacketov = math.ceil((len(celySuborBajty)) / (maxDlzkaPacketu - HLAVICKA_SUBOR))
                checkSpojenie = spojenieSubor(clientSocket, clientAddressPort, pocetPacketov, nazovSuboru)
                if checkSpojenie == "ok":
                    print("Dobre Spojenie")
                    bufferOfDataPocitadlo = int(0)
                    bufferOfData = [b''] * 10
                    for i in range(0, len(celySuborBajty), int(maxDlzkaPacketu) - HLAVICKA_SUBOR):
                        bufferOfData[bufferOfDataPocitadlo] = celySuborBajty[i: i + int(maxDlzkaPacketu) - HLAVICKA_SUBOR]
                        if poslatChybnyPacket == "ano":
                            posliChybnyPacketSubor(clientSocket, clientAddressPort, bufferOfData[bufferOfDataPocitadlo], aktualnyPacket)
                            poslatChybnyPacket = "nie"
                        else:
                            posliPacketSubor(clientSocket, clientAddressPort, bufferOfData[bufferOfDataPocitadlo], aktualnyPacket)
                        if (bufferOfDataPocitadlo == 9) or i + int(maxDlzkaPacketu) - HLAVICKA_SUBOR >= len(celySuborBajty):
                            skontrolujFeedbackSubor(clientSocket, clientAddressPort, bufferOfData, aktualnyPacket)
                            bufferOfDataPocitadlo = -1
                        bufferOfDataPocitadlo += 1
                        aktualnyPacket += 1
                    bolPoslanySubor = "ano"
                else:
                    print("Nespravne spojenie")
            elif typOperacie == 'm':
                pomocnaPremena = "nie"
                if bolPoslanySubor == "ano":
                    pomocnaPremena = "ano"
                bolPoslanySubor = "nie"
                aktualnyPacket = int(1)
                maxDlzkaPacketu = nacitajMaxDlzkuPacketuSprava()
                sprava = input("Zadaj spravu, ktoru chces poslat: ")
                poslatChybnyPacket = input("Chces poslat chybny packet ano/nie: ")
                pocetPacketov = math.ceil(len(sprava) / (maxDlzkaPacketu - HLAVICKA_SPRAVA))
                checkSpojenie = spojenieSprava(clientSocket, clientAddressPort, pocetPacketov)
                if checkSpojenie == "ok":
                    print("Dobre Spojenie")
                    bufferOfMessagesPocitadlo = 0
                    bufferOfMessages = [""] * 10
                    for i in range(0, len(sprava), int(maxDlzkaPacketu) - HLAVICKA_SPRAVA):
                        bufferOfMessages[bufferOfMessagesPocitadlo] = sprava[i: i + int(maxDlzkaPacketu) - HLAVICKA_SPRAVA]
                        if poslatChybnyPacket == "ano":
                            posliChybnyPacketSprava(clientSocket, clientAddressPort, bufferOfMessages[bufferOfMessagesPocitadlo], aktualnyPacket)
                            poslatChybnyPacket = "nie"
                        else:
                            posliPacketSprava(clientSocket, clientAddressPort, bufferOfMessages[bufferOfMessagesPocitadlo], aktualnyPacket)
                        if (bufferOfMessagesPocitadlo == 9) or i + int(maxDlzkaPacketu) - HLAVICKA_SPRAVA >= len(sprava):
                            skontrolujFeedbackSprava(clientSocket, clientAddressPort, bufferOfMessages, aktualnyPacket)
                            bufferOfMessagesPocitadlo = -1
                        bufferOfMessagesPocitadlo += 1
                        aktualnyPacket += 1
                    bolPoslanySubor = pomocnaPremena
                else:
                    print("Nespravne spojenie")
            elif typOperacie == 'k':
                bolPoslanySubor = "nie"
                skonciSpojenie(clientSocket, clientAddressPort)
                clientSocket.close()
                break
            else:
                print("Vysielajuci uzol nepodporuje tuto operaciu.\n")
    elif typUzlu == 'p':
        serverPort = int(input("Zadaj port: "))
        serverAddressPort = ('', serverPort)
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        serverSocket.bind(serverAddressPort)
        print("Pripraveny na prijimanie dat.")
        while True:
            celeData = b''
            celaSprava = ""
            prijatyNazov = ""
            prvyZlyPacket = int(0)
            pocetPacketov = int(1)
            prijateBajty = serverSocket.recvfrom(BUFFER_SIZE)
            dataType = chr(prijateBajty[0][0])
            if dataType == '1':
                (dataType, checksum, conn, msgOrFile, numPacket) = struct.unpack("cHcci", prijateBajty[0][0:HLAVICKA_SPOJENIE])
                if int(msgOrFile) == 3:
                    if int(dataType) == 1 and int(conn) == 1 and int(msgOrFile) == 3 and checksum == binascii.crc_hqx(b'1' + b'0' + b'1' + b'3' + bytes(numPacket), 0):
                        odozvaSpojenieSprava(serverSocket, prijateBajty, numPacket)
                        while pocetPacketov <= numPacket:
                            prijateBajty = serverSocket.recvfrom(BUFFER_SIZE)
                            (dataType, checksum, currentPacket) = struct.unpack("cHi", prijateBajty[0][0:HLAVICKA_SPRAVA])
                            if int(dataType) == 3 and int(currentPacket) == pocetPacketov and checksum == binascii.crc_hqx(b'3' + b'0' + bytes(currentPacket) + prijateBajty[0][HLAVICKA_SPRAVA:], 0) and prvyZlyPacket == 0:
                                celaSprava += prijateBajty[0][HLAVICKA_SPRAVA:].decode("utf-8")
                                print("Cislo packetu: " + str(currentPacket))
                                print("Velkost packetu:", len(prijateBajty[0]))
                            else:
                                if prvyZlyPacket == 0:
                                    prvyZlyPacket = pocetPacketov
                            if currentPacket % 10 == 0 or pocetPacketov == numPacket:
                                celaSprava = posliFeedbackSprava(serverSocket, prijateBajty, celaSprava, prvyZlyPacket)
                                prvyZlyPacket = int(0)
                            pocetPacketov += 1
                        odosielatel = "\nClient IP Address: {}".format(prijateBajty[1])
                        print(odosielatel)
                        print("Pocet packetov: " + str(pocetPacketov - 1))
                        print("Sprava: " + celaSprava + "\n")
                    else:
                        odozvaZleSpojenie(serverSocket, prijateBajty)
                elif int(msgOrFile) == 4:
                    prijatyBezChyb = "ano"
                    if int(dataType) == 1 and int(conn) == 1 and int(msgOrFile) == 4 and checksum == binascii.crc_hqx(b'1' + b'0' + b'1' + b'4' + bytes(numPacket) + prijateBajty[0][HLAVICKA_SPOJENIE:], 0):
                        prijatyNazov = prijateBajty[0][HLAVICKA_SPOJENIE:].decode("utf-8")
                        odozvaSpojenieSubor(serverSocket, prijateBajty, numPacket)
                        while pocetPacketov <= numPacket:
                            prijateBajty = serverSocket.recvfrom(BUFFER_SIZE)
                            (dataType, checksum, currentPacket) = struct.unpack("cHi", prijateBajty[0][0:HLAVICKA_SUBOR])
                            if int(dataType) == 4 and int(currentPacket) == pocetPacketov and checksum == binascii.crc_hqx(b'4' + b'0' + bytes(currentPacket) + prijateBajty[0][HLAVICKA_SUBOR:], 0) and prvyZlyPacket == 0:
                                celeData += prijateBajty[0][HLAVICKA_SUBOR:]
                                if pocetPacketov <= 10:
                                    print("Cislo packetu: " + str(currentPacket))
                                    print("Velkost packetu:", len(prijateBajty[0]))
                            else:
                                if prvyZlyPacket == 0:
                                    prvyZlyPacket = pocetPacketov
                                    prijatyBezChyb = "nie"
                            if currentPacket % 10 == 0 or pocetPacketov == numPacket:
                                celeData = posliFeedbackSubor(serverSocket, prijateBajty, celeData, prvyZlyPacket)
                                prvyZlyPacket = int(0)
                            pocetPacketov += 1
                        newFile = open(prijatyNazov, "wb")
                        newFile.write(celeData)
                        newFile.close()
                        odosielatel = "\nClient IP Address and Port: {}".format(prijateBajty[1])
                        print(odosielatel)
                        ulozisko = os.path.abspath(prijatyNazov)
                        print(ulozisko)
                        print("Nazov suboru: " + prijatyNazov)
                        if prijatyBezChyb == "nie":
                            print("Subor nebol prijaty bez chyb.")
                        else:
                            print("Subor bol prijaty bez chyb.")
                        print("Pocet packetov: " + str(pocetPacketov - 1) + "\n")
                    else:
                        odozvaZleSpojenie(serverSocket, prijateBajty)
                else:
                    odozvaZleSpojenie(serverSocket, prijateBajty)
            elif dataType == '5':
                (dataType, checksum) = struct.unpack("cH", prijateBajty[0][0:HLAVICKA_KEEPALIVE])
                if int(dataType) == 5 and checksum == binascii.crc_hqx(b'5' + b'0', 0):
                    print("Prisiel keepalive")
                    posliKeepAliveOdozvu(serverSocket, prijateBajty)
                else:
                    posliKeepAliveZluOdozvu(serverSocket, prijateBajty)
            elif dataType == '6':
                (dataType, checksum) = struct.unpack("cH", prijateBajty[0][0:HLAVICKA_SKONCI_SPOJENIE])
                if int(dataType) == 6 and checksum == binascii.crc_hqx(dataType + b'0', 0):
                    print("Prijimaci uzol sa zavrel na vyziadanie.")
                    break
            else:
                odozvaZleSpojenie(serverSocket, prijateBajty)
        serverSocket.close()
    elif typUzlu == 'k':
        break
    else:
        print("Program tuto operaciu nepodporuje.\n")


# if int(dataType) == 3 and pocetPacketov == int(currentPacket) and checksum == binascii.crc_hqx(
#         b'3' + b'0' + bytes(currentPacket) + prijateBajty[0][HLAVICKA_SPRAVA:], 0):
#     bufferPrijataSprava[pocitadloBuffer] = prijateBajty[0][HLAVICKA_SPRAVA:].decode("utf-8")
#     bufferPrijataSpravaPoradie[pocitadloBuffer] = int(currentPacket)
#     pocitadloBuffer += 1
#     pocetPacketov += 1
# else:
#     while pocitadloBuffer < currentPacket - 1:
#         bufferPrijataSpravaPoradie[pocitadloBuffer] = int(0)
#         pocitadloBuffer += 1
#         pocetPacketov += 1




