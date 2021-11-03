import os
import struct
import sys
import time
import select
from socket import *
from statistics import stdev, mean
from decimal import Decimal as D



ICMP_ECHO_REQUEST = 8
ICMP_ECHO_RESPONSE = 0


def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer



def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout

    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if not whatReady[0]:  # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fetch the ICMP header from the IP packet
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        icmppacket = recPacket[20:28]
        header = struct.unpack("bbHHh", icmppacket)
        received_type = header[0]
        received_code = header[1]
        received_checksum = header[2]
        received_id = header[3]
        received_sequence = header[4]

        if received_type == ICMP_ECHO_RESPONSE and ID == received_id:
            icmpdata = recPacket[28:]
            time_sent = struct.unpack("d", icmpdata)
            delay = (timeReceived - time_sent[0]) * 1000
            return str(delay)

        if timeLeft - howLongInSelect < 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data

    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str


def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
    mySocket = socket(AF_INET, SOCK_RAW, icmp)

    myID = os.getpid() & 0xFFFF
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay


def ping(host, timeout=1):
    try:
        dest = gethostbyname(host)
    except gaierror:
        return ['0', '0.0', '0', '0.0']

    print("Pinging " + dest + " using Python:\n")
    delays = []

    # Send ping requests to a server separated by approximately one second
    for i in range(0,4):
        delay = doOnePing(dest, timeout)
        if delay != "Request timed out.":
            delays.append(D(delay))
        print(delay)
        time.sleep(1)  # one second

    # Calculate vars values and return them
    if delays:
        results = [str(round(min(delays), 2)), str(round(mean(delays), 2)), str(round(max(delays), 2)), str(round(stdev(delays), 2))]
    else:
        results = ['0', '0.0', '0', '0.0']
    return results

if __name__ == '__main__':
    statistics = ping("google.co.il")
    # statistics = ping("No.no.e")
    # statistics = ping("localhost")
    print(statistics)
