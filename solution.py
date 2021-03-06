from socket import *
import sys
import struct
import time
import select


ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1


def get_checksum(string):
# In this function we make the checksum of our packet
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


def build_packet():
    # Make a dummy header with a 0 checksum and a dummy identifier
    code = 0
    checksum = 0
    identifier = 60000
    sequence = 1
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, code, checksum, identifier, sequence)
    data = struct.pack("d", time.time())

    # Get the right checksum
    checksum = get_checksum(header + data)

    # Convert 16-bit integers from host to network  byte order
    if sys.platform == 'darwin':
        checksum = htons(checksum) & 0xffff
    else:
        checksum = htons(checksum)
    # Create a new header with the new checksum
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, code, checksum, identifier, sequence)

    packet = header + data
    return packet


def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace 
    tracelist2 = [] #This is your list to contain all traces


    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)

            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                icmp_packet = build_packet()
                # mySocket.sendto(d, (hostname, 0))
                mySocket.sendto(icmp_packet, (destAddr, 0))
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if not whatReady[0]: # Timeout
                    tracelist1.append(str(ttl))
                    tracelist1.append("*")
                    tracelist1.append("Request timed out.")
                    tracelist2.append(tracelist1)
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append(str(ttl))
                    tracelist1.append("*")
                    tracelist1.append("Request timed out.")
                    tracelist2.append(tracelist1)
            except timeout:
                continue

            else:
                # Fetch the icmp type from the IP packet, it is the first byte after the IP header
                types = struct.unpack("b", recvPacket[20:21])[0]
                try:
                    responseHostName = gethostbyaddr(addr[0])
                except herror:
                    responseHostName = "hostname not returnable"

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 +
                    bytes])[0]
                    tracelist1.append(str(ttl))
                    tracelist1.append(str((timeReceived - timeSent) * 1000))
                    tracelist1.append(addr[0])
                    tracelist1.append(responseHostName)
                    tracelist2.append(tracelist1)
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    tracelist1.append(str(ttl))
                    tracelist1.append(str((timeReceived - timeSent) * 1000))
                    tracelist1.append(addr[0])
                    tracelist1.append(responseHostName)
                    tracelist2.append(tracelist1)
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    tracelist1.append(str(ttl))
                    tracelist1.append(str((timeReceived - timeSent) * 1000))
                    tracelist1.append(addr[0])
                    tracelist1.append(responseHostName)
                    tracelist2.append(tracelist1)
                    if addr[0] == destAddr:
                        return tracelist2
                else:
                    tracelist2.append(list("*** Error ***"))
                break
            finally:
                mySocket.close()