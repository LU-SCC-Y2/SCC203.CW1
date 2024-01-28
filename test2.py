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
        icmpHeader = struct.pack('bbHHh', 8, 0, socket.htons(icmpCheckSum), ID, 1)
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
                    print("Round-trip time exceeded the specified timeout", timeout)
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
        # 1. Create ICMP socket
        icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # 2. Call sendOnePing function
        sendPing = self.sendOnePing(icmpSocket, destinationAddress, packetID)
        # 3. Call receiveOnePing function
        receivePing = self.receiveOnePing(icmpSocket, destinationAddress, packetID, timeout)
        if receivePing is not None:
            # 4. Unpack the received tuple
            delay, ttl, packetSize, sequence = receivePing
            # 5. Close ICMP socket
            icmpSocket.close()
            # 6. Print out the delay (and other relevant details) using the printOneResult method
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
    def makeICMPPacket(self, ID):
        icmpHeader = struct.pack('bbHHh', 8, 0, 0, ID, 1)
        icmpData = b'JIAJUNdaBEST' 
        icmpCheckSum = self.checksum(icmpHeader + icmpData)
        icmpHeader = struct.pack('bbHHh', 8, 0, socket.htons(icmpCheckSum), ID, 1)
        icmpPacket = icmpHeader + icmpData

        return icmpPacket
    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))
        self.protocol = args.protocol.lower() if args.protocol else 'icmp'
        self.timeout = args.timeout if args.timeout else 2
        self.destinationAddress = socket.gethostbyname(args.hostname)

        if self.protocol == 'udp':
            self.traceroute_udp()
        elif self.protocol == 'icmp':
            self.traceroute_icmp()
        else:
            print("Invalid protocol specified.")

    def traceroute_udp(self):
        port = 33434  # Start with the default traceroute UDP port
        max_hops = 30
        ttl = 1

        while ttl <= max_hops:
            
            try:
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
                udp_socket.settimeout(self.timeout)
                udp_socket.bind(('', port))
                udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

                udp_socket.sendto(b'', (self.destinationAddress, port))
                start_time = time.time()
                print('hello')

                data, addr = udp_socket.recvfrom(1024)
                print("addr: ", addr)
                end_time = time.time()
                delay = (end_time - start_time) * 1000  # in milliseconds
                udp_socket.close()
                host = socket.gethostbyaddr(addr[0])[0]
                self.printOneTraceRouteIteration(ttl, addr[0], [delay], host)
            except socket.timeout:
                self.printOneTraceRouteIteration(ttl, '*', [None])
            except Exception as e:
                print(f"Error: {e}")
            ttl += 1

    def traceroute_icmp(self):
        max_hops = 5
        ttl = 1

        while ttl <= max_hops:
            
            try:
                icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, struct.pack('I', ttl))
                icmp_socket.settimeout(self.timeout)
                packet_id = int((id(icmp_socket) / 1000) % 65535)  # Unique ID for each packet
                icmp_packet = self.makeICMPPacket(packet_id)
                
                icmp_socket.sendto(icmp_packet, (self.destinationAddress, 33434))
                start_time = time.time()
                data, addr = icmp_socket.recvfrom(1024)
                end_time = time.time()
                delay = (end_time - start_time) * 1000  # in milliseconds
                icmp_socket.close()
                host = socket.gethostbyaddr(addr[0])[0]
                self.printOneTraceRouteIteration(ttl, addr[0], [delay], host)
            except socket.timeout:
                self.printOneTraceRouteIteration(ttl, '*', [None])
            except Exception as e:
                print(f"Error: {e}")
            ttl += 1



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
