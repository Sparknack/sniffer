from util import toAscii,byte2bin, str2hex, str2byte, hexstr2unicode, get_mac, get_ipv4, get_ipv6, get_timestamp, hexstr2bytes
import time

class Ether(object):
    next_proto_map = {'0806': 'arp', '0800': 'ipv4','86dd':'ipv6'}
    header_length = 14  # bytes

    def __init__(self, header):
        self.d_mac = get_mac(header[:12])
        self.s_mac = get_mac(header[12:24])
        self.type = header[24:28]
        self.next_proto = Ether.next_proto_map[self.type]
        self.time = time.time()

    def summary(self):
        print("d_mac : %s" % self.d_mac)
        print("s_mac : %s" % self.s_mac)
        print("next proto : %s" % self.next_proto)


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

    def summary(self):
        print('----ARP---')
        print('opcode %s ' % self.opcode)
        print('sender_ip_address %s ' % self.sender_ip_address)
        print('sender_mac_address %s ' % self.sender_mac_address)
        print('target_ip_address %s ' % self.target_ip_address)
        print('target_mac_address %s ' % self.target_mac_address)

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

    def summary(self):
        print('----IPv4----')
        print('version %s ' % self.version)
        print('header_length %d ' % self.header_length)
        print('total_length %d ' % self.total_length)
        print('next_proto %s ' % self.next_proto)
        print('source %s ' % self.source)
        print('destination %s ' % self.destination)

    def info(self):
        return 'IPv4:unfinished'

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

    def summary(self):
        print('----IPv6----')
        print('version %s ' % self.version)
        print('traffic class %s ' % self.traffic_class)
        print('differentiated service codepoint %d ' % self.differentiated_service_codepoint)
        print('explicit congestion notification %d ' % self.explicit_congestion_notification)
        print('flow label %s ' % self.flow_label)
        print('payload length %d ' % self.payload_length)
        print('next protocal %s ' % self.next_proto)
        print('hop limit %d ' % self.hop_limit)
        print('source %s ' % self.source)
        print('destination %s ' % self.destination)

    def info(self):
        return "IPV6 Unfinished"

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

    def summary(self):
        print('----ICMP----')
        print(self.data)

    def info(self):
        info = ''
        if self.type+self.code in self.type_list:
            info = self.type_list[self.type+self.code]+' id='+ self.identifier_be+' seq=' + self.sequence_number_be
        else:
            info = "Can't indentify"+' id='+ self.identifier_be+' seq=' + self.sequence_number_be
        return info

class Icmpv6(object):
    def __init__(self, header):
        pass

    def info(self):
        return "ICMPv6 need to be complished."

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
        self.segment_data_length = tcp_total_length - self.header_length
        self.actual_data = b''
        self.stream_index = self.source_port + self.destination_port
        self.get_data(data)

    def get_data(self, data):
        if self.segment_data_length > 0:
            self.actual_data = hexstr2bytes(data[self.header_length*2:])

    # def get_proto(self, data):
    #     if self.segment_data_length > 0:
    #         if self.source_port == 80 or self.destination_port == 80:
    #             self.get_data(data)
    #             if b'HTTP/' in self.actual_data:
    #                 self.next_proto = 'http'
    #         elif self.source_port == 443 or self.destination_port == 443:
    #             self.next_proto = 'TSL'

    def get_options(self,options_data):
        option_name = {'00':'EOL','01':'NOP','02':'MSS','03':'WS','04':'SACK Permitted','05':'SACK','06':'Echo','07':'Echo Reply','08':'Timestamps'}
        option_length = {'00':0,'01':0,'02':4,'03':3,'04':2,'06':6,'07':6,'08':10}
        '''
        waiting to complete
        '''
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

    def summary(self):
        print('----TCP----')
        print('source_port : %d' % self.source_port)
        print('destination_port : %d' % self.destination_port)
        print('sequence_number : %d' % self.sequence_number)
        print('acknowledgement_number : %d' % self.acknowledgement_number)
        print('header_length : %d' % self.header_length)
        print('syn : %s' % self.syn)
        print('ack : %s' % self.ack)
        print('push : %s' % self.push)
        print('fin : %s' % self.fin)
        print('window_size_value : %d' % self.window_size_value)
        print('segment_data_length : %d' % self.segment_data_length)
        if self.actual_data:
            print('---DATA---')
            print(self.actual_data)
        if self.next_proto:
            print('TOP PROTO is : %s' % self.next_proto)


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

    def summary(self):
        print('----DNS----')
        print('query_name : %s' % self.query_name)

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

    def stream_index(self):
        pass
    # def get_data(self,header):
    #     if self.length > 8:
    #         if (self.source_port == 53 or self.destination_port ==53):
    #             self.dns = Dns(header[16:])

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
        return 'UDP info unfinished'

    def summary(self):
        print('----UDP----')
        print('source_port : %d' % self.source_port)
        print('destination_port : %d' % self.destination_port)
        print('length : %d' % self.length)
        print('checksum : %s' % self.checksum)


class Igmp(object):
    def __init__(self,header):
        self.type = header[:2]
        self.max_resp_time = int(header[2:4],16)/10
        self.check_sum = header[4:8]
        self.multicast_address = get_ipv4(header[8:16])


class Smtp(object):
    def __init__(self, header):
        pass


class Tsl(object):
    content_type = {'16': 'handshake', '14': 'chang_cipher_spec', '17': 'application_data', '15': 'alert', '18': 'heartbeat'}

    def __init__(self, header):
        self.content_type = Tsl.content_type[header[:2]]
        self.version = header[2:6]
        self.length = int(header[6:10], 16)


class HandShake(object):
    handshake_type = {'00': 'hello_request', '01': 'client_hello', '02': 'server_hello', '0b': 'certificate', '0c': 'server_key_exchange', '0d': 'certificate_requset', '0e': 'server_done', '0f': 'certificate_verify', '10': 'client_key_exchange', '14': 'finished'}

    def __init__(self, header):
        pass


class ChangeCiperSpec(object):

    def __init__(self):
        pass


class Alert(object):

    def __init__(self):
        pass


class ApplicationData(object):

    def __init__(self):
        pass


slice = ''
class Packet(object):
    def __init__(self, raw_packet):
        # self.stream_packet = str2byte(raw_packet)
        # if (isinstance(raw_packet,str)
        self.stream_packet = raw_packet
        header = self.stream_packet[:Ether.header_length*2]
        self.length = len(raw_packet)//2
        self.ether = Ether(header)
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
            header = self.stream_packet[Ether.header_length*2:]
            self.arp = Arp(header)
            self.proto = 'arp'

        elif self.ether.next_proto == 'ipv4':
            ip_header_length = int(self.stream_packet[Ether.header_length*2+1],16)*4
            header = self.stream_packet[Ether.header_length*2:Ether.header_length*2+ip_header_length*2]
            self.ipv4 = Ipv4(header)

            if int(self.ipv4.flags[2]):
                self.ipv4.next_proto = ''
                self.proto = 'ipv4'
                if self.ipv4.fragment_offset == 0:
                    slice = self.stream_packet[Ether.header_length*2+ip_header_length*2:]
                elif self.ipv4.fragment_offset != 0:
                    slice = slice + self.stream_packet[Ether.header_length*2+ip_header_length*2:]

            if self.ipv4.next_proto == "tcp":
                tcp_total_length = self.ipv4.total_length - self.ipv4.header_length
                header = self.stream_packet[Ether.header_length*2+ip_header_length*2:]
                self.tcp = Tcp(header, tcp_total_length)
                self.proto = 'tcp'

            elif self.ipv4.next_proto == 'udp':
                slice = slice + self.stream_packet[Ether.header_length*2+ip_header_length*2:]
                header = slice[:8*2]
                self.udp = Udp(header)
                self.length = len(slice) + Ether.header_length * 2 + ip_header_length * 2
                self.stream_packet = self.stream_packet[:Ether.header_length*2] + self.stream_packet[Ether.header_length * 2:Ether.header_length * 2 + ip_header_length * 2] + slice
                self.proto = 'udp'
                if self.udp.source_port == 53 or self.udp.destination_port == 53:
                    self.dns = Dns(slice[8*2:])
                    self.proto = 'dns'
                slice = ''

            elif self.ipv4.next_proto == 'icmp':
                slice = slice + self.stream_packet[Ether.header_length*2+ip_header_length*2:]
                self.icmp = Icmp(slice)
                self.length = len(slice)+Ether.header_length*2+ip_header_length*2
                self.stream_packet = self.stream_packet[:Ether.header_length*2]+self.stream_packet[Ether.header_length*2:Ether.header_length*2+ip_header_length*2]+slice
                self.icmp.data = hexstr2bytes(slice)
                slice = ''
                self.proto = 'icmp'

        elif self.ether.next_proto == 'ipv6':
            header = self.stream_packet[Ether.header_length * 2:Ether.header_length * 2 + 40 * 2]
            self.ipv6 = Ipv6(header)
            self.proto = 'ipv6'
            if self.ipv6.next_proto == 'icmpv6':
                header = self.stream_packet[Ether.header_length * 2 + 40*2:]
                self.icmpv6 = Icmpv6(header)
                self.proto = 'icmpv6'
        else:
            return "no such proto"

        self.ascii_data = toAscii(self.stream_packet)

    def summary(self):
        self.ether.summary()
        if self.ipv4:
            self.ipv4.summary()
            if self.tcp:
                self.tcp.summary()
            elif self.icmp:
                self.icmp.summary()
            elif self.udp:
                self.udp.summary()
                if self.dns:
                    self.dns.summary()
            else:
                print("can't judge the proto after ip")
        elif self.arp:
            self.arp.summary()

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

