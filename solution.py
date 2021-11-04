from socket import *
import sys
import struct
import time
import select


ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1


def checksum(string):
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
    # dummy identifier (processid/portnumber) initial checksum 0 to create the header and store it as bytes
    code = 0
    myChecksum = 0
    identifier = 60000
    sequence = 1
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, code, myChecksum, identifier, sequence)

    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the header.
    myChecksum = checksum(header + data)

    # Convert 16-bit integers from host to network byte order
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    # Create a new header with the new checksum in Big-Endian notation
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, code, myChecksum, identifier, sequence)

    packet = header + data
    return packet


def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace 
    tracelist2 = [] #This is your list to contain all traces


    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)

            mySocket = socket(AF_INET, SOCK_RAW, getprotobyname("icmp"))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)

            try:
                icmpPacket = build_packet()
                # mySocket.sendto(icmpPacket, (hostname, 0))
                mySocket.sendto(icmpPacket, (destAddr, 0))
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
                # Fetch the icmp type from the IP packet
                # type field is the first after the IP header
                type = struct.unpack("b", recvPacket[20:21])[0]
                try:
                    responseHostName = gethostbyaddr(addr[0])
                except herror:
                    responseHostName = "hostname not returnable"

                if type == 11:
                    bytes = struct.calcsize("icmpPacket")
                    timeSent = struct.unpack("icmpPacket", recvPacket[28:28 +
                    bytes])[0]
                    tracelist1.append(str(ttl))
                    tracelist1.append(str((timeReceived - timeSent) * 1000))
                    tracelist1.append(addr[0])
                    tracelist1.append(responseHostName)
                    tracelist2.append(tracelist1)
                elif type == 3:
                    bytes = struct.calcsize("icmpPacket")
                    timeSent = struct.unpack("icmpPacket", recvPacket[28:28 + bytes])[0]
                    tracelist1.append(str(ttl))
                    tracelist1.append(str((timeReceived - timeSent) * 1000))
                    tracelist1.append(addr[0])
                    tracelist1.append(responseHostName)
                    tracelist2.append(tracelist1)
                elif type == 0:
                    bytes = struct.calcsize("icmpPacket")
                    timeSent = struct.unpack("icmpPacket", recvPacket[28:28 + bytes])[0]
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
