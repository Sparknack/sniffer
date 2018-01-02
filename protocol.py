from util import toAscii,byte2bin, str2hex, str2byte, hexstr2unicode, get_mac, get_ipv4, get_ipv6, get_timestamp, hexstr2bytes
import time

class Ethernet(object):
    next_proto_map = {'0806': 'arp', '0800': 'ipv4','86dd':'ipv6'}
    header_length = 14  # bytes

    def __init__(self, header):
        self.d_mac = get_mac(header[:12])
        self.s_mac = get_mac(header[12:24])
        self.type = header[24:28]
        self.next_proto = Ethernet.next_proto_map[self.type]
        self.time = time.time()

class Arp(object):
    header_length = 28*2

    def __init__(self, header):
        self.hardware_type = header[:4]
        self.protocol_type = header[4:8]
        self.hardware_size = header[8:10]
        self.protocol_size = header[10:12]
        self.opcode = header[12:16]
        self.sender_mac_address = get_mac(header[16:28])
        self.sender_ip_address = get_ipv4(header[28:36])
        self.target_mac_address = get_mac(header[36:48])
        self.target_ip_address = get_ipv4(header[48:56])

    def info(self):
        return "Who has "+self.target_ip_address+"? Tell "+self.sender_ip_address

class Ipv4(object):
    # header_length = 20*2
    next_proto_map = {'06': 'tcp', '11': 'udp', '01': 'icmp'}

    def __init__(self, header):
        self.version = header[0]
        self.header_length = int(header[1], 16)*4  # bytes
        self.dsf = header[2:4]
        self.total_length = int(header[4:8], 16)  # bytes
        self.identification = header[8:12]
        self.flags = byte2bin(header[12:14])[:3]
        self.fragment_offset = byte2bin(header[12:16])[3:]
        self.time_to_live = header[16:18]  # ttl
        self.next_proto = Ipv4.next_proto_map[header[18:20]]
        self.checksum = header[20:24]
        self.source = get_ipv4(header[24:32])
        self.destination = get_ipv4(header[32:40])

    def checksum_verify(self, header):
        header.replace(header[20:24], '0000')
        checksum_calc = '0000'
        word_num = int(len(header) / 4)
        for i in range(word_num):
            checksum_int = int(header[4 * i:4 * i + 4], 16) + int(checksum_calc, 16)
            checksum_calc = hex(checksum_int).replace('0x', '')
            while len(checksum_calc) > 4:
                checksum_calc = '000' + checksum_calc
                checksum_int = int(checksum_calc[4:], 16) + int(checksum_calc[0:4], 16)
                checksum_calc = hex(checksum_int).replace('0x', '')
        checksum_calc = hex((int(checksum_calc, 16) ^ (16 * 16 * 16 * 16 - 1))).replace('0x', '')
        while len(checksum_calc) < 4:
            checksum_calc = '0' + checksum_calc
        if self.checksum == checksum_calc:
            return 1
        else:
            return 0

    def info(self):
        return 'Fragmented IPv4 protocol'

class Ipv6(object):
    next_proto_map = {'06': 'tcp', '11': 'udp', '01': 'icmp','3a':'icmpv6'}

    def __init__(self,header):
        self.version = header[0]
        self.traffic_class = '0x'+header[1:3]
        self.differentiated_service_codepoint = int(byte2bin(header[1:3])[:6],2)
        self.explicit_congestion_notification = int(byte2bin(header[1:3])[6:],2)
        self.flow_label = '0x'+header[3:8]
        self.payload_length = int(header[8:12],16)
        self.next_proto = Ipv6.next_proto_map[header[12:14]]
        self.hop_limit = int(header[14:16],16)
        self.source = get_ipv6(header[16:48])
        self.destination = get_ipv6(header[48:80])

    def info(self):
        return "Fragmented IPv6 protocol"

class Icmp(object):
    header_length = 16*2
    type_list = {'0800':'Echo (ping) request','0000':'Echo reply','0b00':'Time out'}
    def __init__(self,data):
        self.type = data[:2]
        self.code = data[2:4]
        self.checksum = data[4:8]
        self.identifier_be = data[8:12]
        self.identifier_le = self.identifier_be[2:4]+self.identifier_be[:2]
        self.sequence_number_be = data[12:16]
        self.sequence_number_le = self.sequence_number_be[2:4]+self.sequence_number_be[:2]
        self.timestamp_from_icmp_data = get_timestamp(data[16:32])
        self.data_length = len(data[32:])//2
        self.data = hexstr2bytes(data[32:])
        self.data_hex = data[32:]

    def checksum_verify(self, data):
        data = data.replace(data[4:8], '0000')
        checksum_calc = '0000'
        if len(data) % 4:
            data = data[:-2] + '00' + data[-2:]
        word_num = int(len(data) / 4)
        for i in range(word_num):
            checksum_int = int(data[4 * i:4 * i + 4], 16) + int(checksum_calc, 16)
            checksum_calc = hex(checksum_int).replace('0x', '')
            while len(checksum_calc) > 4:
                checksum_calc = '000' + checksum_calc
                checksum_int = int(checksum_calc[4:], 16) + int(checksum_calc[0:4], 16)
                checksum_calc = hex(checksum_int).replace('0x', '')
        checksum_calc = hex((int(checksum_calc, 16) ^ (16 * 16 * 16 * 16 - 1))).replace('0x', '')
        while len(checksum_calc) < 4:
            checksum_calc = '0' + checksum_calc
        if self.checksum == checksum_calc:
            return 1
        else:
            return 0

    def info(self):
        info = ''
        if self.type+self.code in self.type_list:
            info = self.type_list[self.type+self.code]+' id='+ self.identifier_be+' seq=' + self.sequence_number_be
        else:
            info = "Can't indentify"+' id='+ self.identifier_be+' seq=' + self.sequence_number_be
        return info

class Icmpv6(object):
    type_list = {1:'Destination Unreachable',2:'Packet Too Big',3:'Time Exceeded',4:'Parameter Problem',128:'Echo Request',129:'Echo Reply',133:'Router Solicitation',134:'Router Advertisement'}
    def __init__(self, header):
        self.type = int(header[:2],16)
        self.code = int(header[2:4],16)
        self.checksum = header[4:8]
        self.cur_hop_limit = int(header[8:10],16)
        self.flags = byte2bin(header[10:12])
        self.router_lifetime = int(header[12:16],16)
        self.reachable_time = int(header[16:24],16)
        self.retrans_time = int(header[24:32],16)
        self.icmpv6_options = header[32:]

    def info(self):
        if self.type in self.type_list:
            return self.type_list[self.type]
        else:
            return "Type:"+str(self.type)

class Tcp(object):
    flags_name = ['NONCE','CWR','ECN','URG','ACK','PUSH','RESET','SYN','FIN']
    def __init__(self, data, tcp_total_length):
        '''
        data be the part of tcp
        tcp_total_length = ip.total_length - ip_header_length
        '''
        self.source_port = int(data[:4], 16)
        self.destination_port = int(data[4:8], 16)
        self.sequence_number = int(data[8:16], 16)
        self.acknowledgement_number = int(data[16:24], 16)
        self.header_length = int(data[24], 16)*4  # bytes
        self.reserved = byte2bin(data[25:28])[:3]
        self.flags = byte2bin(data[25:28])[3:]
        # self.nonce = self.flags[0]
        # self.cwr = self.flags[1]
        # self.ecn = self.flags[2]
        # self.urgent = self.flags[3]
        # self.reset = self.flags[6]
        # self.syn = self.flags[7]
        # self.ack = self.flags[4]
        # self.push = self.flags[5]
        # self.fin = self.flags[8]
        self.window_size_value = int(data[28:32], 16)
        self.checksum = data[32:36]
        self.urgent_pointer = data[36:40]
        self.options = data[40:self.header_length*2]
        self.kind = []
        self.segment_data_length = tcp_total_length - self.header_length
        self.actual_data = b''
        self.stream_index = self.source_port + self.destination_port
        self.get_data(data)
        if self.options:
            self.get_options(self.options)

    def get_data(self, data):
        if self.segment_data_length > 0:
            self.actual_data = hexstr2bytes(data[self.header_length*2:])

    def get_options(self,options_data):
        option_name_list = {'00':'EOL','01':'NOP','02':'MSS','03':'WS','04':'SACK Permitted','05':'SACK','08':'Timestamps'}
        option_length_list = {'00':1,'01':1,'02':4,'03':3,'04':2,'08':10}
        while options_data:
            self.kind.append(option_name_list[options_data[:2]])
            options_data = options_data[option_length_list[options_data[:2]]*2:]

    def info(self):
        info = str(self.source_port)+"->"+str(self.destination_port)
        if int(self.flags,2):
            info += ' [ '
            for i in range(9):
                if int(self.flags[i]):
                    info = info + self.flags_name[i]+' '
            info += ']'
        info = info+' Seq='+str(self.sequence_number)+' Ack='+str(self.acknowledgement_number)+' Win='+str(self.window_size_value)+' Len='+str(self.header_length-20)
        return info

    def checksum_verify(self, data, ip_header):
        data = data.replace(data[32:36], '0000')
        tcp_length = hex(int(ip_header[4:8], 16) - 20).replace('0x', '')
        while len(tcp_length) < 4:
            tcp_length = '0' + tcp_length
        pseudo_header = ip_header[24:40] + '0006' + tcp_length
        data = pseudo_header + data
        checksum_calc = '0000'
        if len(data) % 4:
            data = data[:-2] + '00' + data[-2:]
        word_num = int(len(data) / 4)
        for i in range(word_num):
            checksum_int = int(data[4 * i:4 * i + 4], 16) + int(checksum_calc, 16)
            checksum_calc = hex(checksum_int).replace('0x', '')
            while len(checksum_calc) > 4:
                checksum_calc = '000' + checksum_calc
                checksum_int = int(checksum_calc[4:], 16) + int(checksum_calc[0:4], 16)
                checksum_calc = hex(checksum_int).replace('0x', '')
        checksum_calc = hex((int(checksum_calc, 16) ^ (16 * 16 * 16 * 16 - 1))).replace('0x', '')
        while len(checksum_calc) < 4:
            checksum_calc = '0' + checksum_calc
        if self.checksum == checksum_calc:
            return 1
        else:
            return 0


class Dns(object):
    message_type = {'0': 'query', '1': 'response'}
    def __init__(self, header):
        self.transaction_id = header[:4]
        self.flags = byte2bin(header[4:8])
        self.response = Dns.message_type[self.flags[0]]
        self.questions = int(header[8:12], 16)
        self.answer_rrs = int(header[12:16], 16)
        self.authority_rrs = int(header[16:20], 16)
        self.additional_rrs = int(header[20:24], 16)
        if self.response == 'query':
            self.query_name = hexstr2bytes(header[24:-8])
            self.query_type = header[-8:-4]
            self.query_class = header[-4:]
        else:
            self.answer_data = hexstr2bytes(header[24:])

    def info(self):
        info = 'Standard query '
        if int(self.flags[0]):
            info += 'response '
        info = info+str(self.transaction_id)
        return info

class Udp(object):
    def __init__(self, header):
        self.source_port = int(header[:4], 16)
        self.destination_port = int(header[4:8], 16)
        self.length = int(header[8:12], 16)
        self.checksum = header[12:16]

    def checksum_verify(self, data, ip_header):
        data = data.replace(data[12:16], '0000')
        udp_length = hex(int(ip_header[4:8], 16) - 20).replace('0x', '')
        while len(udp_length) < 4:
            udp_length = '0' + udp_length
        pseudo_header = ip_header[24:40] + '0011' + udp_length
        data = pseudo_header + data
        checksum_calc = '0000'
        if len(data) % 4:
            data = data[:-2] + '00' + data[-2:]
        word_num = int(len(data) / 4)
        for i in range(word_num):
            checksum_int = int(data[4 * i:4 * i + 4], 16) + int(checksum_calc, 16)
            checksum_calc = hex(checksum_int).replace('0x', '')
            while len(checksum_calc) > 4:
                checksum_calc = '000' + checksum_calc
                checksum_int = int(checksum_calc[4:], 16) + int(checksum_calc[0:4], 16)
                checksum_calc = hex(checksum_int).replace('0x', '')
        checksum_calc = hex((int(checksum_calc, 16) ^ (16 * 16 * 16 * 16 - 1))).replace('0x', '')
        while len(checksum_calc) < 4:
            checksum_calc = '0' + checksum_calc
        if self.checksum == checksum_calc:
            return 1
        else:
            return 0

    def info(self):
        return 'Fragmented UDP protocol'


class Igmp(object):
    def __init__(self,header):
        self.type = header[:2]
        self.max_resp_time = int(header[2:4],16)/10
        self.check_sum = header[4:8]
        self.multicast_address = get_ipv4(header[8:16])

slice = ''
class Packet(object):

    def __init__(self, raw_packet):
        # self.stream_packet = str2byte(raw_packet)
        # if (isinstance(raw_packet,str)
        self.stream_packet = raw_packet
        header = self.stream_packet[:Ethernet.header_length * 2]
        self.length = len(raw_packet)//2
        self.ether = Ethernet(header)
        self.proto = None
        self.arp = None
        self.ipv4 = None
        self.ipv6 = None
        self.tcp = None
        self.udp = None
        self.dns = None
        self.icmp = None
        self.icmpv6 = None
        global slice

        if self.ether.next_proto == 'arp':
            header = self.stream_packet[Ethernet.header_length * 2:]
            self.arp = Arp(header)
            self.proto = 'arp'

        elif self.ether.next_proto == 'ipv4':
            ip_header_length = int(self.stream_packet[Ethernet.header_length * 2 + 1], 16) * 4
            header = self.stream_packet[Ethernet.header_length * 2:Ethernet.header_length * 2 + ip_header_length * 2]
            self.ipv4 = Ipv4(header)

            if int(self.ipv4.flags[2]):
                self.ipv4.next_proto = ''
                self.proto = 'ipv4'
                if self.ipv4.fragment_offset == 0:
                    slice = self.stream_packet[Ethernet.header_length * 2 + ip_header_length * 2:]
                elif self.ipv4.fragment_offset != 0:
                    slice = slice + self.stream_packet[Ethernet.header_length * 2 + ip_header_length * 2:]

            if self.ipv4.next_proto == "tcp":
                tcp_total_length = self.ipv4.total_length - self.ipv4.header_length
                header = self.stream_packet[Ethernet.header_length * 2 + ip_header_length * 2:]
                self.tcp = Tcp(header, tcp_total_length)
                self.proto = 'tcp'

            elif self.ipv4.next_proto == 'udp':
                slice = slice + self.stream_packet[Ethernet.header_length * 2 + ip_header_length * 2:]
                header = slice[:8*2]
                self.udp = Udp(header)
                self.length = len(slice)//2 + Ethernet.header_length+ ip_header_length
                self.stream_packet = self.stream_packet[:Ethernet.header_length * 2] + self.stream_packet[Ethernet.header_length * 2:Ethernet.header_length * 2 + ip_header_length * 2] + slice
                self.proto = 'udp'
                if self.udp.source_port == 53 or self.udp.destination_port == 53:
                    self.dns = Dns(slice[8*2:])
                    self.proto = 'dns'
                slice = ''

            elif self.ipv4.next_proto == 'icmp':
                slice = slice + self.stream_packet[Ethernet.header_length * 2 + ip_header_length * 2:]
                self.icmp = Icmp(slice)
                self.length = len(slice)//2 + Ethernet.header_length + ip_header_length
                self.stream_packet = self.stream_packet[:Ethernet.header_length * 2] + self.stream_packet[Ethernet.header_length * 2:Ethernet.header_length * 2 + ip_header_length * 2] + slice
                self.icmp.data = hexstr2bytes(slice)
                slice = ''
                self.proto = 'icmp'

        elif self.ether.next_proto == 'ipv6':
            header = self.stream_packet[Ethernet.header_length * 2:Ethernet.header_length * 2 + 40 * 2]
            self.ipv6 = Ipv6(header)
            self.proto = 'ipv6'
            if self.ipv6.next_proto == 'icmpv6':
                header = self.stream_packet[Ethernet.header_length * 2 + 40 * 2:]
                self.icmpv6 = Icmpv6(header)
                self.proto = 'icmpv6'
        else:
            return "no such proto"

        self.ascii_data = toAscii(self.stream_packet)

    def info(self):
        if self.arp:
            return self.arp.info()
        if self.tcp:
            return self.tcp.info()
        elif self.icmp:
            return self.icmp.info()
        elif self.dns:
            return self.dns.info()
        elif self.udp:
            return self.udp.info()
        elif self.ipv4:
            return self.ipv4.info()
        elif self.icmpv6:
            return self.icmpv6.info()
        elif self.ipv6:
            return self.ipv6.info()

