#!/usr/bin/env python3
import os
import socket
import struct
import sys
import time

# some defines
ICMP_ECHO_REQUEST = 8  # type 8 echo request
ICMP_ECHO_REPLY = 0  # type 0 reply
ICMP_HDR_SIZE = 8
IP_HDR_SIZE = 20
PACKET_HEADER = 28
MAX_PACKET_SIZE = 1500

'''
receiver handles receiving icmp packets use raw sockets with recvfrom() 
param: socket_reciver, raw socket instance
return: icmp_header, header of icmp
        icmp_data, payload of icmp
'''


def reciver(socket_reciver):
    # wait for recive
    time.sleep(1)
    print("---------------Waiting for receiving from the receiver---------------")
    packet, addr = socket_reciver.recvfrom(MAX_PACKET_SIZE)
    print("Received packet from :", addr)
    icmp_header = packet[IP_HDR_SIZE:PACKET_HEADER]
    icmp_data = packet[PACKET_HEADER:]
    return icmp_header, icmp_data


'''
unpack_ICMP unpack the incoming packet to icmp type, code, checksum and id...
param: icmp_data, data
return: icmp_reply_header, header for out icmp
'''


def unpack_ICMP(icmp_hdr, icmp_data):
    icmp_type, icmp_code, icmp_checksum, icmp_packet_ID, sequence = struct.unpack('bbHHh', icmp_hdr)
    print('\n----------------------------ICMP PAYLOAD----------------------------\n')
    print(icmp_data)
    print('\n')
    # write_file(icmp_data)


'''
write_file helps to write the icmp payload to local file
param: icmp_data, data
return: None
output: sender_icmp.txt
'''
def write_file(icmp_data):
    # print("I need to see icmp data", icmp_data)
    decode_data = icmp_data.decode("utf-8")
    output_file = 'sender_icmp.txt'
    # print('Writing icmp data to', output_file)
    print('\n----------------------Storing icmp data to {filename}---------------------\n'.format(filename=output_file))
    try:
        with open(output_file, "w") as f:
            f.writelines(decode_data)
            print('ICMP data has been stored in {filename} successfully'.format(filename=output_file))
            f.close()
    except FileNotFoundError:
        print('{filename} not found'.format(filename=output_file))
    except FileExistsError:
        print('{filename} exists'.format(filename=output_file))


'''
checksum helps to calculate checksum
param: icmp_packet
return: None
checksum reference RFC 1071: https://www.rfc-editor.org/rfc/rfc1071,https://www.codeproject.com/Tips/460867/Python-Implementation-of-IP-Checksum
'''
def checksum(icmp_packet):
    len_packet = len(icmp_packet)
    sum = 0
    buff = 0
    while len_packet > 1:
        sum += int((str("%02x" % (icmp_packet[buff],)) +
                      str("%02x" % (icmp_packet[buff + 1],))), 16)
        buff += 2
        len_packet -= 2
    if len_packet:
        cksum += ip_header[buff]
    sum = (sum >> 16) + (sum & 0xffff)
    # fold 32 to 16bits
    sum = sum + (sum >> 16)
    result = (~sum) & 0xFFFF
    print("answer:", result)
    return result

'''
pack_packet pack packet with modified data contains 256-28 bytes
return: icmp_header
        icmp_data, payload 
'''

def pack_packet():
    # set up variables for icmp
    icmp_cksum = 0
    # icmp_cksum = checksum(icmp_cksum)
    icmp_id = 0
    icmp_data = b'\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F'  # payload part

    icmp_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, icmp_cksum, icmp_id, 1)
    return icmp_header, icmp_data

'''
pack_packet pack packet with modified data contains 256-28 bytes
param: icmp_socket, raw socket
       icmp_header, header of icmp
       icmp_data, payload of icmp
       dest_addr, destination address
return: icmp_header
        icmp_data, payload 
'''
def send_packet(icmp_socket, icmp_header, icmp_data, dest_addr):
    # Calculate the checksum on the data and the dummy header.
    icmp_id = 0
    icmp_cksum = checksum(icmp_header + icmp_data)
    # # Get the right checksum, and put in the header
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, icmp_cksum, icmp_id, 1)
    packet = header + icmp_data
    data_len = len(icmp_data)
    # destAddr = '127.0.0.1'
    # packet = ip_header + header + data
    packet_out = icmp_socket.sendto(packet, (dest_addr, 1))
    print('\n--------------Sending packet to the receiver {d_addr}--------------\n'.format(d_addr=dest_addr))
    print('Packet size', packet_out)
    print('\n')
    # print('Ping: {pkt}, {host}'.format(pkt=struct.unpack('bbHHh', packet[:-data_len]), host=dest_addr))


if __name__ == "__main__":
    if len(sys.argv) == 2:
        target = sys.argv[1]
    else:
        print('Usage: python ' + sys.argv[0] + " <target ip address>")
        sys.exit()

    seq = n = 0
    icmp_seq = 0
    icmp_ttl = 60
    count = 1

    # create a raw socket with ICMP protocol
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print('You must be root', file=sys.stderr)
        exit(1)
    except:
        print('Error in create socket', file=sys.stderr)
        exit(1)

    # bind the raw socket with host
    # host_ip = '10.0.0.120'
    HOST = socket.gethostbyname(socket.gethostname())
    try:
        raw_socket.bind((HOST, 0))
    except:
        print('Error in create socket', file=sys.stderr)
        exit(1)

    # ping starts here
    # pack the packet
    icmp_header, icmp_data = pack_packet()
    # send the packet to the dest
    send_packet(raw_socket, icmp_header, icmp_data, target)
    time.sleep(2)
    send_packet(raw_socket, icmp_header, icmp_data, target)
    # received and store the data
    icmp_header, icmp_data = reciver(raw_socket)
    # unpack the icmp received
    unpack_ICMP(icmp_header, icmp_data)
    # write file to local
    write_file(icmp_data)

    time.sleep(2)
    print('------------------------------DONE------------------------------')
    print('\n')
    raw_socket.close()
