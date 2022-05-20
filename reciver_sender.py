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
        cnt, counter use to identify the order of packets received 
return: packet, incoming data packet
        dest_addr, the source address
        cnt, counter
'''
def reciver(socket_reciver, cnt):
    packet, dest_addr = socket_reciver.recvfrom(MAX_PACKET_SIZE)
    cnt += 1
    print('\n--------------Waiting for receiving packet from {d_addr}--------------\n'.format(d_addr=dest_addr[0]))
    # print("Received packet from :", dest_addr)
    print('\n')
    return packet, dest_addr, cnt

'''
extract_ICMP_data helps to extract the payload part of icmp from the whole IP packet 
param: packet, data
return: icmp_data, data
'''
def extract_ICMP_data(packet):
    print('Packet size: ', len(packet) - IP_HDR_SIZE)
    icmp_data = packet[PACKET_HEADER:]
    print('\n----------------------------ICMP PAYLOAD----------------------------\n')
    # print('Received ICMP Data: {buffer} '.format(buffer=icmp_data))
    print(icmp_data)
    print('\n')
    # # write to the file only when the sec packet received
    # if cnt == 2:
    #     write_file(icmp_data)
    return icmp_data

'''
write_file helps to write the icmp payload to local file
param: icmp_data, data
return: None
output file: receiver_icmp.txt
'''
def write_file(icmp_data):
    decode_data = icmp_data.decode("utf-8")
    output_file = 'receiver_icmp.txt'
    print('\n----------------------Storing icmp data to {filename}---------------------\n'.format(filename=output_file))
    # print('Writing icmp data to', output_file)
    # print('\n')
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
unpack_and_pack unpack the incoming packet to icmp type, code, checksum and id, and pack the icmp header with modified data
param: icmp_data, data
return: icmp_reply_header, header for out icmp
'''
def unpack_and_pack(packet):
    icmp_hdr = packet[IP_HDR_SIZE:PACKET_HEADER]
    # icmp_hdr = struct.unpack('!BBHHH', icmp_hdr)
    icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence = struct.unpack('bbHHh', icmp_hdr)
    # print('Receiving packet: ICMP type : {type}  ICMP code : {code}  ICMP cks : {checksum} ICMP id: {id}, ICMP seq:{sequence}'
    #       '\n'.format(type=icmp_type, code=icmp_code, checksum=icmp_checksum, id=icmp_id,
    #                   sequence=icmp_sequence))
    time.sleep(1)
    icmp_type = ICMP_ECHO_REPLY
    icmp_sequence = icmp_sequence + 1
    # icmp_data = packet[iph_length + IP_HDR_SIZE:]

    # sending icmp reply back
    icmp_reply_header = struct.pack("bbHHh", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence)
    # print('Sending packet: ICMP type : {type}  ICMP code : {code}  ICMP cks : {checksum} ICMP id: {id}, ICMP seq:{sequence}'
    #       '\n'.format(type=icmp_hdr_type, code=icmp_code, checksum=icmp_checksum, id=icmp_packet_ID,
    #                   sequence=sequence))
    # packet_out = header + icmp_data
    # data_len = len(icmp_data)
    return icmp_reply_header

'''
send_packet func class sendto to send out the packet that passed in to this function
param: icmp_data, data
return: icmp_reply_header, header for out icmp
'''
def send_packet(socket_reciver, packet_out, dest_addr):
    print('---------------sending reply back to {addr}---------------'.format(addr=dest_addr[0]))
    print('\n')
    time.sleep(2)
    # try:
    socket_reciver.sendto(packet_out, (dest_addr[0], 1))
    # except socket_reciver.timeout:
    #     print('Host is down')
    #     return 1
    # except:
    #     print('Fatal: General error in recvfrom()', file=sys.stderr)
    #     exit(1)
    # print('packet out look like',packet_out)
    # print('Ping: {pkt}, {host}'.format(pkt=struct.unpack('bbHHh', packet_out[:-data_len]), host=dest_addr))
    time.sleep(2)
    print('------------------------------DONE------------------------------')
    print('\n')
    socket_reciver.close()


if __name__ == "__main__":
    # counter for receiver packets
    rec_cnt = 0
    tot_data = ""
    for x in range(0,2):
        # create the raw socket with AF_INET and IPPROTO_ICMP protocol
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # waiting for the first packet to be received,
        packet_received, dest_addr, rec_cnt = reciver(raw_socket, rec_cnt)
        # store the data part when its the first packet received
        if rec_cnt == 1:
            # extract data and buffer it
            tot_data = extract_ICMP_data(packet_received)
            raw_socket.close()
        # print("range ", x)
        # print("counter", rec_cnt)
        # time.sleep(3)
        if rec_cnt == 2:
            # extract data portion
            icmp_data2 = extract_ICMP_data(packet_received)
            tot_data = tot_data + icmp_data2
            # write both data in file
            write_file(tot_data)
            # unpack the packet, we need some icmp info to reply the request
            icmp_reply_header = unpack_and_pack(packet_received)
            # merge the icmp header with its payload
            packet_out = icmp_reply_header + tot_data
            # send a respond back to the application who started the ping
            send_packet(raw_socket, packet_out, dest_addr)
            raw_socket.close()
