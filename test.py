#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading
# NOTE: Do not import any other modules - the ones above should be sufficient

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=10, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:
    def checksum(self, dataToChecksum: bytes) -> int:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printOneTraceRouteIteration(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):
    def makeICMPPacket(self, ID):
        icmpHeader = struct.pack('bbHHh', 8, 0, 0, ID, 1)
        icmpData = b'JIAJUNdaBEST' 
        icmpCheckSum = self.checksum(icmpHeader + icmpData)
        icmpHeader = struct.pack('bbHHh', 8, 0, icmpCheckSum, ID, 1)
        icmpPacket = icmpHeader + icmpData

        return icmpPacket
    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        try:
            startTime = time.time()
            receivedPacket, address = icmpSocket.recvfrom(1024)
            endTime = time.time()

            receivedICMP = receivedPacket[20:28]
            Type, Code, checksum, packetID, sequence = struct.unpack('bbHHh', receivedICMP)
            ttl = struct.unpack('B', receivedPacket[8:9])[0]
            
            if address[0] == destinationAddress and packetID == ID:
                if (endTime - startTime) * 1000 > timeout:
                    print("Round-trip timeout", timeout)
                    raise socket.timeout()
                return endTime - startTime, ttl, len(receivedICMP), sequence
            
            elif Type == 3 and Code == 0:
                return "Destination Network Unreachable"
            elif Type == 3 and Code == 1:
                return "Destination Host Unreachable"
            
        except socket.timeout:
            print("Timeout")
            return None
        
    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        icmpPacket = self.makeICMPPacket(ID)
        # 5. Send packet using socket
        icmpSocket.sendto(icmpPacket, (destinationAddress, 1))
        # 6. Return time of sending
        return time.time()

    def doOnePing(self, destinationAddress, packetID, seq_num, timeout):
        icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sendPing = self.sendOnePing(icmpSocket, destinationAddress, packetID)
        receivePing = self.receiveOnePing(icmpSocket, destinationAddress, packetID, timeout)
        if receivePing is not None:
            delay, ttl, packetSize, sequence = receivePing
            icmpSocket.close()
            self.printOneResult(destinationAddress, packetSize, delay * 1000, seq_num, ttl, args.hostname)
        return receivePing

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        destinationIP = socket.gethostbyname(args.hostname)
        minimumDelay, maximumDelay, lostPackets, total = float('inf'), 0, 0, 0

        # 2. Repeat below args.count times
        for i in range(args.count):
            # 3. Call doOnePing function, approximately every second, below is just an example
            result = self.doOnePing(destinationIP, i, i, args.timeout)
            if result is not None:
                delay, ttl, packetSize, seq = result
                delay *= 1000
                total += delay

                if delay < minimumDelay:
                    minimumDelay = delay

                if delay > maximumDelay:
                    maximumDelay = delay
            else:
                lostPackets += 1
            time.sleep(1)
        lostPercentage = (lostPackets / args.count) * 100
        averageDelay = total / (args.count) - lostPackets
        self.printAdditionalDetails(lostPercentage, minimumDelay, averageDelay, maximumDelay)

class Traceroute(NetworkApplication):
    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))
        self.protocol = args.protocol.lower()
        destinationAddress = socket.gethostbyname(args.hostname)     

        if self.protocol == "icmp":   
            for ttl in range(1, 31): 
                reached = self.doICMPtraceroute(destinationAddress, ttl, args)
                if reached:
                    break
        elif self.protocol == "udp":
            for ttl in range(1, 31): 
                reached = self.doUDPtraceroute(destinationAddress, ttl, args)
                if reached:
                    break

    def makeICMPsocket(self, ttl, args):
        icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        icmpSocket.settimeout(args.timeout) 
        return icmpSocket
    
    def makeICMPPacket(self):
        icmpHeader = struct.pack('bbHHh', 8, 0, 0, 1, 1) 
        icmpData = b'JIAJUNdaBEST'
        icmpChecksum = self.checksum(icmpHeader + icmpData)
        icmpHeader = struct.pack('bbHHh', 8, 0, icmpChecksum, 1, 1)
        icmpPacket = icmpHeader + icmpData
        return icmpPacket
    
    def makeUDPsocket(self, ttl, args):
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        udpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        udpSocket.settimeout(args.timeout)
        udpSocket.bind(('', 0))      
        return udpSocket
    
    def doICMPtraceroute(self, destinationAddress, ttl, args):
        delays, detailedDelays = [], []
        address = None
        reached = False
        for i in range(3):
            icmpSocket = self.makeICMPsocket(ttl, args)
            
            icmpPacket = self.makeICMPPacket()
            icmpSocket.sendto(icmpPacket, (destinationAddress, 33434)) 
            try:
                start_time = time.time() 
                receivedPacket, address = icmpSocket.recvfrom(1024)
                end_time = time.time()
                delay = (end_time - start_time) * 1000
                
                if delay < args.timeout:
                    delays.append(delay)
                    detailedDelays.append(delay)
                else:
                    delays.append(None)
                    detailedDelays.append(0)
                receivedICMP = receivedPacket[20:28]
                
                Type, Code, checksum, packetID, sequence = struct.unpack('bbHHh', receivedICMP)
                ttlive = struct.unpack('B', receivedPacket[8:9])[0]
                # print(f"Type: {Type}, Code: {Code}, Checksum: {checksum}, PacketID: {packetID}, Sequence: {sequence}, TTLive: {ttlive} | ttl: {ttl}")
                if Type == 0: 
                    reached = True
                icmpSocket.close()

                try:
                    destinationHostname = socket.gethostbyaddr(address[0])[0]
                except socket.herror:
                    destinationHostname = ''

                #self.printOneResult(address[0], len(receivedPacket), delay, i, ttlive, destinationHostname)

            except socket.timeout:
                delays.append(None)
                continue

        if address is not None:          
            self.printOneTraceRouteIteration(ttl, address[0], delays, destinationHostname)
        else:
            self.printOneTraceRouteIteration(ttl, "", delays)
        print("-" * 90)
        return reached
 
    def doUDPtraceroute(self, destinationAddress, ttl, args):
        delays, detailedDelays = [], []
        address = None
        reached = False
        for i in range(3):
            icmpSocket = self.makeICMPsocket(ttl, args)

            udpSocket = self.makeUDPsocket(ttl, args)
            udpSocket.sendto(b'', (destinationAddress, 33434))
            
            try:
                start_time = time.time()
                receivedPacket, address = icmpSocket.recvfrom(1024)
                end_time = time.time()
                delay = (end_time - start_time) * 1000
                
                if delay < args.timeout:
                    delays.append(delay)
                    detailedDelays.append(delay)
                else:
                    delays.append(None)
                    detailedDelays.append(0)

                receivedICMP = receivedPacket[20:28]
                Type, Code, checksum, packetID, sequence = struct.unpack('bbHHh', receivedICMP)
                ttlive = struct.unpack('B', receivedPacket[8:9])[0]

                print("Type: ", Type)
                if (Type == 3):
                    reached = True
                icmpSocket.close()
                try:
                    destinationHostname = socket.gethostbyaddr(address[0])[0]
                except socket.herror:
                    destinationHostname = ''

            except socket.timeout:
                delays.append(None)
                continue
                
        if address is not None:          
            self.printOneTraceRouteIteration(ttl, address[0], delays, destinationHostname)
        else:
            self.printOneTraceRouteIteration(ttl, "", delays)
        print("-" * 90)
        return reached

class WebServer(NetworkApplication):

    def handleRequest(tcpSocket):
        # 1. Receive request message from the client on connection socket
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        # 2. Bind the server socket to server address and server port
        # 3. Continuously listen for connections to server socket
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))

# Do not delete or modify the code below
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)