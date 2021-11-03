from socket import *
import os
import sys
import struct
import time
import select
import binascii

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
    # Make the header in a similar way to the ping exercise.
    myChecksum = 0
    processID = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, processID, 1)
    data = struct.pack("d", time.time())

    myChecksum = checksum(header + data)
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, processID, 1)
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace
    tracelist2 = [] #This is your list to contain all traces

    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)

            # Make a raw socket named mySocket
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                packet = build_packet()
                mySocket.sendto(packet, (destAddr, 0))
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if not whatReady[0]: # Timeout
                    # tracelist1.append("* * * Request timed out.")
                    # hop = [str(ttl), "*", "Request timed out."]
                    tracelist1.append(str(ttl))
                    tracelist1.append("*")
                    tracelist1.append("Request timed out.")
                    #You should add the list above to your all traces list
                    tracelist2.append(tracelist1)
                recvPacket, sourceAddr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append(str(ttl))
                    tracelist1.append("*")
                    tracelist1.append("Request timed out.")
                    # You should add the list above to your all traces list
                    tracelist2.append(tracelist1)
            except timeout:
                continue
            else:
                #Fetch the icmp type from the IP packet
                type = struct.unpack("b", recvPacket[0:1])[0]
                try:
                    sourceHostName = gethostbyaddr(sourceAddr[0])
                except herror:
                    sourceHostName = "hostname not returnable"

                if type == 11:
                    timeSent = struct.unpack("d", recvPacket[28:28 + struct.calcsize("d")])[0]
                    #You should add your responses to your lists here
                    # hop = [str(ttl), str((timeReceived - timeSent) * 1000), sourceAddr[0], sourceHostName]
                    tracelist1.append(str(ttl))
                    tracelist1.append(str((timeReceived - timeSent) * 1000))
                    tracelist1.append(sourceAddr[0])
                    tracelist1.append(sourceHostName)
                    tracelist2.append(tracelist1)
                elif type == 3:
                    timeSent = struct.unpack("d", recvPacket[28:28 + struct.calcsize("d")])[0]
                    # You should add your responses to your lists here
                    tracelist1.append(str(ttl))
                    tracelist1.append(str((timeReceived - timeSent) * 1000))
                    tracelist1.append(sourceAddr[0])
                    tracelist1.append(sourceHostName)
                    tracelist2.append(tracelist1)
                elif type == 0:
                    timeSent = struct.unpack("d", recvPacket[28:28 + struct.calcsize("d")])[0]
                    # You should add your responses to your lists here
                    tracelist1.append(str(ttl))
                    tracelist1.append(str((timeReceived - timeSent) * 1000))
                    tracelist1.append(sourceAddr[0])
                    tracelist1.append(sourceHostName)
                    tracelist2.append(tracelist1)
                    #return your list if your destination IP is met
                    return tracelist2
                else:
                    tracelist1.append("*** Error ***")
                    tracelist2.append(tracelist1)
                break
            finally:
                mySocket.close()
                return tracelist2

result = get_route("gaia.cs.umass.edu")
print(result)
# get_route("localhost")