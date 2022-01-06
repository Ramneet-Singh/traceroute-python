#!/usr/bin/env python3

# A Python script to emulate the traceroute functionality. For reasons mentioned
# in https://wiki.geant.org/display/public/EK/VanJacobsonTraceroute I use ICMP
# Echo Packets instead of UDP Datagrams. The script takes as a command line
# input the domain name of the intended receiver. It works by sending ICMP echo
# messages to the destination with increasing values of the IPv4 TTL Field. It
# listens to receive an ICMP Time Exceeded message from the routers along the
# path, and an ICMP Reply message from the final destination. The IP Addresses
# of the routers that send messages are extracted from the message header, and
# the round trip times are calculated using a timer on the sender.
# Written By: Ramneet Singh, 2019CS50445, IIT Delhi

import sys
import socket
import struct
import random
import time
import select
import numpy as np
from matplotlib.colors import ListedColormap
import matplotlib.pyplot as plt
import seaborn as sns
sns.set()

ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp')

# ----- DEFAULTS -----
NUM_PROBES = 3
MAX_TTL = 64
TIMEOUT = 5

"""
Take as input a dictionary of hop number vs average RTT, and plot the graph.
Save the graph in a file named rtt_plot.png
"""
def plotRtt(plotPoints):
    lists = sorted(plotPoints.items())
    x, y = zip(*lists)
    values = []
    for rtt in y:
        value = 0
        if rtt==0:
            value = 1
        values.append(value)
    values[len(values)-1] = 2
    classes = ["Intermediate Routers", "No Response", "Target Destination"]
    colors = ListedColormap(['b', 'r', 'g'])
    scatter = plt.scatter(x,y, c=values, cmap=colors, alpha=0.75)
    plt.title("Average Round Trip Time (RTT) vs Hop Number")
    plt.xlabel("Hop Number")
    plt.xticks(range(1, len(x)+1))
    plt.ylabel("Average RTT (in ms)")
    plt.legend(handles=scatter.legend_elements()[0], labels=classes)
    plt.savefig("rtt_plot.png")

"""
    Receive a response for the packet that we sent. Handle timeout.
    Return (hostAddress, roundTripTime) and ("*", -1) in case of timeout.
"""
def receive(icmpSocket, packetId, timeSent, timeout):
    timeLeft = timeout
    # Wait until we either receive a response or our timeout expires. Use the select module for blocking.
    while True:
        startedSelect = time.time()
        ready = select.select([icmpSocket], [], [], timeLeft)
        howLongInSelect = time.time() - startedSelect
        if ready[0] == []:
            return ("*", -1) # Timeout
        timeReceived = time.time()
        receivedPacket, ipAddr = icmpSocket.recvfrom(1024)
        # Last 8 Bytes contain the header of the packet we sent
        icmpHeader = receivedPacket[-8:]
        _, _, _, pId, _ = struct.unpack( # Type, Code, Checksum, Packet ID, Sequence Number
            "bbHHh", icmpHeader
        )
        if pId == packetId:
            roundTripTime = (timeReceived - timeSent)*1000 # in ms
            roundTripTime = round(roundTripTime, 3)
            return (ipAddr[0], roundTripTime)

        timeLeft -= howLongInSelect
        if timeLeft <= 0:
            return ("*", -1) # Timeout


""" Calculate the checksum of a bytes array. Written with reference to pyping module. """
def findChecksum(string):
    sum = 0
    count_to = (len(string) / 2) * 2
    count = 0

    # Handle bytes in pairs
    while count < count_to:
        this_val = (string[count + 1])*256 + (string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff # Truncate to 32 bits
        count = count + 2

    # Handle last byte if applicable (odd-number of bytes)
    if count_to < len(string):
        sum = sum + (string[len(string) - 1])
        sum = sum & 0xffffffff # Truncate to 32 bits

    sum = (sum >> 16) + (sum & 0xffff) # Add high 16 bits to low 16 bits
    sum = sum + (sum >> 16) # Add carry from above, if any
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

""" Build an ICMP Echo request packet with given id. """
def buildPacket(packet_id : int):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    checksum = 0

    # Make a dummy header with a 0 checksum.
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, checksum, packet_id, 1
    )

    data = ''.encode('utf-8')

    # Calculate the checksum on the data and the dummy header.
    checksum = findChecksum(header + data)

    # Construct the new header. The htons() function makes sure that numbers are
    # stored in memory in network byte order, which is with the most significant
    # byte first. (big-endian, as opposed to hosts which are little-endian mostly)
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum), packet_id, 1
    )
    return (header + data)


""" Send an ICMP Echo request packet, and receive its response. Return (hostAddress, roundTripTime) and ("*", -1) if there's no response. """
def sendProbe(destAddr : str, ttl : int):
    # Create raw socket for ICMP Messages
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    # Now we build the packet
    packet_id = int(random.random() * 65535) # We have to fit the ID into 16 Bytes (unsigned short int in C) hence 65535
    packet = buildPacket(packet_id)
    # Send the packet
    while packet:
        sent = icmp_socket.sendto(packet, (destAddr, 1344)) # Give a dummy port even though icmp protocol doesn't need one
        packet = packet[sent:]

    # Receive the response for this packet
    response = receive(icmp_socket, packet_id, time.time(), TIMEOUT)
    icmp_socket.close()
    return response

"""
Send NUM_PROBES probes to the destination host and listen for a response. Return
an array of (hostAddress, roundTripTime) with ("*", -1) when there's no
response, and also a boolean indicating whether we have reached the destination.
"""
def sendProbes(destAddr : str, ttl : int):
    reached = False
    responses = []

    for i in range(NUM_PROBES):
        response = sendProbe(destAddr, ttl)
        if response[0] == destAddr:
            reached = True
        responses.append(response)

    return (responses, reached)

""" Main Loop of the Program. Controls sending, receiving and printing info. """
def traceloop(destAddr : str):
    plotPoints = {}
    for ttl in range(1, MAX_TTL+1):
        if ttl<10:
            print(f" {ttl}\t", end="")
        else:
            print(f"{ttl}\t", end="")

        (probeRes, destReached) = sendProbes(destAddr, ttl)
        hostRtt = {}
        avgRtt, numRtt = 0, 0
        for res in probeRes:
            if res[0]!= "*":
                numRtt += 1
                avgRtt += res[1]
                if res[0] not in hostRtt:
                    hostRtt[res[0]] = f" {res[1]} ms"
                else:
                    hostRtt[res[0]] += f" {res[1]} ms"
            else:
                if "empty" not in hostRtt:
                    hostRtt["empty"] = "*"
                else:
                    hostRtt["empty"] += " *"

        if(numRtt>0):
            avgRtt = (avgRtt / numRtt)
        plotPoints[ttl] = avgRtt

        first = True
        for host in hostRtt:
            indentString = ""
            if(not first):
                indentString = "  \t"
            if host != "empty":
                print(indentString + f"{host} ({host}){hostRtt[host]}")
            else:
                print(indentString + hostRtt[host])
            first = False
        if destReached:
            break
    # Plot the RTT vs Hop Number curve and save
    plotRtt(plotPoints)


if __name__=="__main__":
    try:
        destName = sys.argv[1]
    except IndexError:
        raise SystemExit(f"Missing Domain Name\nUsage: {sys.argv[0]} <public_domain_name>")

    destAddr = socket.gethostbyname(destName)

    print(f"traceroute to {destName} ({destAddr}), {MAX_TTL} hops max")

    traceloop(destAddr)
