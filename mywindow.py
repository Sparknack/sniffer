from PyQt5 import QtWidgets
from PyQt5.Qt import QTableWidgetItem,QTreeWidgetItem,QListWidgetItem,QFileDialog
from PyQt5.QtCore import pyqtSignal,QThread
import time
import socket
import re
from util import str2hex,toAscii,hexstr2unicode
from protocol import Packet
from UIforsniffer import Ui_MainWindow
import sys,os
import gzip

class mywindow(QtWidgets.QMainWindow,Ui_MainWindow):
    total_pac_list = []
    pac_list = []
    number = 0
    start_time = 0
    filter_button = 0
    interface = None
    condition = None
    thread = None


    def __init__(self):
        super(mywindow,self).__init__()
        self.setupUi(self)
        for i in os.listdir('/sys/class/net/'):
            self.comboBox.addItem(i)
        self.current_row = 0
        self.tableWidget.itemClicked.connect(self.show_detail)
        self.tableWidget.itemClicked.connect(self.show_data)
        self.pushButton_select.clicked.connect(self.sniff_init)
        self.pushButton_export.clicked.connect(self.export_http_file)
        self.pushButton_export_ftp.clicked.connect(self.export_ftp_file)
        self.pushButton_save.clicked.connect(self.save_packets)
        self.pushButton_restart.clicked.connect(self.restart)
        self.pushButton_find.clicked.connect(self.findpacket)

    def sniff_init(self):
        self.interface = self.comboBox.currentText()
        self.thread = SniffThread(self.interface)
        self.thread.sniff_signal.connect(self.load)
        self.thread.start_signal.connect(self.start)
        self.pushButton_filter.clicked.connect(self.filter)
        self.pushButton_start.clicked.connect(lambda: self.thread.start())
        self.pushButton_stop.clicked.connect(lambda: self.thread.terminate())
        self.pushButton_follow_stream.clicked.connect(self.follow_tcp_stream)

#计算抓包的开始时间
    def start(self,time):
        self.start_time = time

#将包在table表格中实时动态显示出来
    def load(self,packets):
        p_row = len(packets)
        self.tableWidget.setRowCount(p_row)
        for i in range(self.number,p_row):
            self.total_pac_list.append(packets[i])
            self.pac_list.append(packets[i])
            self.show_table(packets[i],i)
        self.number = p_row

#对所抓的包进行过滤，暂时只支持stop之后过滤
    def show_table(self,packet,i):
        if packet.arp:
            data = QTableWidgetItem(str(round(packet.ether.time - self.start_time, 6)))
            self.tableWidget.setItem(i, 0, data)
            data = QTableWidgetItem(packet.arp.sender_ip_address)
            self.tableWidget.setItem(i, 2, data)
            data = QTableWidgetItem(packet.arp.target_ip_address)
            self.tableWidget.setItem(i, 1, data)
            data = QTableWidgetItem(str(packet.length))
            self.tableWidget.setItem(i, 4, data)
            data = QTableWidgetItem(packet.proto)
            self.tableWidget.setItem(i, 3, data)
            data = QTableWidgetItem(packet.info())
            self.tableWidget.setItem(i, 5, data)
        elif packet.ipv4:
            data = QTableWidgetItem(str(round(packet.ether.time - self.start_time, 6)))
            self.tableWidget.setItem(i, 0, data)
            data = QTableWidgetItem(packet.ipv4.source)
            self.tableWidget.setItem(i, 2, data)
            data = QTableWidgetItem(packet.ipv4.destination)
            self.tableWidget.setItem(i, 1, data)
            data = QTableWidgetItem(str(packet.length))
            self.tableWidget.setItem(i, 4, data)
            data = QTableWidgetItem(packet.proto)
            self.tableWidget.setItem(i, 3, data)
            data = QTableWidgetItem(packet.info())
            self.tableWidget.setItem(i, 5, data)
        elif packet.ipv6:
            data = QTableWidgetItem(str(round(packet.ether.time - self.start_time, 6)))
            self.tableWidget.setItem(i, 0, data)
            data = QTableWidgetItem(packet.ipv6.source)
            self.tableWidget.setItem(i, 2, data)
            data = QTableWidgetItem(packet.ipv6.destination)
            self.tableWidget.setItem(i, 1, data)
            data = QTableWidgetItem(str(packet.length))
            self.tableWidget.setItem(i, 4, data)
            data = QTableWidgetItem(packet.proto)
            self.tableWidget.setItem(i, 3, data)
            data = QTableWidgetItem(packet.info())
            self.tableWidget.setItem(i, 5, data)

    def filter(self):
        self.condition = self.lineEdit.text()
        if self.condition == '':
            return None
        i = 0
        self.tableWidget.setRowCount(i)
        self.pac_list.clear()
        exec('''for packet in self.total_pac_list:
                if %s:
                    try:
                        if packet.arp:
                            self.tableWidget.setRowCount(i+1)
                            data = QTableWidgetItem(str(round(packets.ether.time-self.start_time,6)))
                            self.tableWidget.setItem(i, 0, data)
                            data = QTableWidgetItem(packet.arp.sender_ip_address)
                            self.tableWidget.setItem(i, 2, data)
                            data = QTableWidgetItem(packet.arp.target_ip_address)
                            self.tableWidget.setItem(i, 1, data)
                            data = QTableWidgetItem(str(packet.length))
                            self.tableWidget.setItem(i, 4, data)
                            data = QTableWidgetItem(packet.proto)
                            self.tableWidget.setItem(i, 3, data)
                            data = QTableWidgetItem(packet.info())
                            self.tableWidget.setItem(i, 5, data)
                        elif packet.ipv4:
                            self.tableWidget.setRowCount(i+1)
                            data = QTableWidgetItem(str(round(packet.ether.time-self.start_time,6)))
                            self.tableWidget.setItem(i, 0, data)
                            data = QTableWidgetItem(packet.ipv4.source)
                            self.tableWidget.setItem(i, 2, data)
                            data = QTableWidgetItem(packet.ipv4.destination)
                            self.tableWidget.setItem(i, 1, data)
                            data = QTableWidgetItem(str(packet.length))
                            self.tableWidget.setItem(i, 4, data)
                            data = QTableWidgetItem(packet.proto)
                            self.tableWidget.setItem(i, 3, data)
                            data = QTableWidgetItem(packet.info())
                            self.tableWidget.setItem(i, 5, data)
                        i = i + 1
                        self.pac_list.append(packet)
                    except:
                        print("filter error")
                 ''' % self.condition)

    def findpacket(self):
        self.condition = self.lineEdit.text()
        if self.condition == '':
            return None
        i = 0
        self.tableWidget.setRowCount(i)
        self.pac_list.clear()
        exec('''for packet in self.total_pac_list:
                if "%s" in packet.ascii_data:
                    try:
                        if packet.arp:
                            self.tableWidget.setRowCount(i+1)
                            data = QTableWidgetItem(str(round(packets.ether.time-self.start_time,6)))
                            self.tableWidget.setItem(i, 0, data)
                            data = QTableWidgetItem(packet.arp.sender_ip_address)
                            self.tableWidget.setItem(i, 2, data)
                            data = QTableWidgetItem(packet.arp.target_ip_address)
                            self.tableWidget.setItem(i, 1, data)
                            data = QTableWidgetItem(str(packet.length))
                            self.tableWidget.setItem(i, 4, data)
                            data = QTableWidgetItem(packet.proto)
                            self.tableWidget.setItem(i, 3, data)
                            data = QTableWidgetItem(packet.info())
                            self.tableWidget.setItem(i, 5, data)
                        elif packet.ipv4:
                            self.tableWidget.setRowCount(i+1)
                            data = QTableWidgetItem(str(round(packet.ether.time-self.start_time,6)))
                            self.tableWidget.setItem(i, 0, data)
                            data = QTableWidgetItem(packet.ipv4.source)
                            self.tableWidget.setItem(i, 2, data)
                            data = QTableWidgetItem(packet.ipv4.destination)
                            self.tableWidget.setItem(i, 1, data)
                            data = QTableWidgetItem(str(packet.length))
                            self.tableWidget.setItem(i, 4, data)
                            data = QTableWidgetItem(packet.proto)
                            self.tableWidget.setItem(i, 3, data)
                            data = QTableWidgetItem(packet.info())
                            self.tableWidget.setItem(i, 5, data)
                        i = i + 1
                        self.pac_list.append(packet)
                    except:
                        print("find error")
                 ''' % self.condition)

#用树形结构显示所选中包的具体协议列表
    def show_detail(self,Item=None):
        if Item==None:
            return
        packet = self.pac_list[int(Item.row())]
        self.current_row = int(Item.row())
        self.treeWidget.clear()
        ether = QTreeWidgetItem(self.treeWidget)
        ether.setText(0,'Ethernet')
        d_mac = QTreeWidgetItem(ether)
        d_mac.setText(0,"Destination:"+packet.ether.d_mac)
        s_mac = QTreeWidgetItem(ether)
        s_mac.setText(0,"Source:"+packet.ether.s_mac)
        type = QTreeWidgetItem(ether)
        type.setText(0,"Type:"+packet.ether.next_proto+'(0x'+packet.ether.type+')')
        self.treeWidget.addTopLevelItem(ether)
        if packet.arp:
            arp = QTreeWidgetItem(self.treeWidget)
            arp.setText(0, 'ARP')
            hw_type = QTreeWidgetItem(arp)
            hw_type.setText(0, "Hardware Type:0x" + packet.arp.hardware_type)
            pro_type = QTreeWidgetItem(arp)
            pro_type.setText(0, "Protocol Type:0x" + packet.arp.protocol_type)
            hw_size = QTreeWidgetItem(arp)
            hw_size.setText(0, "Hareware Size:"+packet.arp.hardware_size)
            pro_size = QTreeWidgetItem(arp)
            pro_size.setText(0,"Protocol Size:"+packet.arp.protocol_size)
            opcode = QTreeWidgetItem(arp)
            opcode.setText(0,"Opcode:"+packet.arp.opcode)
            s_mac_a = QTreeWidgetItem(arp)
            s_mac_a.setText(0, "Sender Mac Address:" + packet.arp.sender_mac_address)
            s_ip_a = QTreeWidgetItem(arp)
            s_ip_a.setText(0, "Sender IP Address:" + packet.arp.sender_ip_address)
            t_mac_a = QTreeWidgetItem(arp)
            t_mac_a.setText(0, "Target Mac Address:" + packet.arp.target_mac_address)
            t_ip_a = QTreeWidgetItem(arp)
            t_ip_a.setText(0, "Target IP Address:" + packet.arp.target_ip_address)
            self.treeWidget.addTopLevelItem(arp)
        elif packet.ipv4:
            ipv4 = QTreeWidgetItem(self.treeWidget)
            ipv4.setText(0,'IPv4')
            version = QTreeWidgetItem(ipv4)
            version.setText(0, "Version:" + packet.ipv4.version)
            hd_len = QTreeWidgetItem(ipv4)
            hd_len.setText(0, "Header Length:" + str(packet.ipv4.header_length))
            dsf = QTreeWidgetItem(ipv4)
            dsf.setText(0, "DSF:" + packet.ipv4.dsf)
            total_len = QTreeWidgetItem(ipv4)
            total_len.setText(0, "Total Length:" + str(packet.ipv4.total_length))
            iden = QTreeWidgetItem(ipv4)
            iden.setText(0, "Identification:" + packet.ipv4.identification)
            flags = QTreeWidgetItem(ipv4)
            flags.setText(0, "Flags:" + packet.ipv4.flags)
            ttl = QTreeWidgetItem(ipv4)
            ttl.setText(0, "TTL(Time to live):" + packet.ipv4.time_to_live)
            next_pro = QTreeWidgetItem(ipv4)
            next_pro.setText(0, "Protocal:" + packet.ipv4.next_proto)
            checksum = QTreeWidgetItem(ipv4)
            checksum.setText(0, "Checksum:" + packet.ipv4.checksum+"(Verified)")
            source = QTreeWidgetItem(ipv4)
            source.setText(0, "Source:" + packet.ipv4.source)
            destination = QTreeWidgetItem(ipv4)
            destination.setText(0, "Destination:" + packet.ipv4.destination)
            self.treeWidget.addTopLevelItem(ipv4)
            if packet.tcp:
                tcp = QTreeWidgetItem(self.treeWidget)
                tcp.setText(0,'TCP')
                s_p = QTreeWidgetItem(tcp)
                s_p.setText(0, "Source Port:" + str(packet.tcp.source_port))
                d_p = QTreeWidgetItem(tcp)
                d_p.setText(0, "Destination Port:" + str(packet.tcp.destination_port))
                seq_num = QTreeWidgetItem(tcp)
                seq_num.setText(0, "Sequence Number:" + str(packet.tcp.sequence_number))
                ack_num = QTreeWidgetItem(tcp)
                ack_num.setText(0, "Acknowledgement Number:" + str(packet.tcp.acknowledgement_number))
                header_len = QTreeWidgetItem(tcp)
                header_len.setText(0, "Header Length:" + str(packet.tcp.header_length))
                reserved = QTreeWidgetItem(tcp)
                reserved.setText(0, "Reserved:" + packet.tcp.reserved)
                flags_tcp = QTreeWidgetItem(tcp)
                flags_tcp.setText(0, "Flags:" + packet.tcp.flags)
                wsv = QTreeWidgetItem(tcp)
                wsv.setText(0, "Window Size Value:" + str(packet.tcp.window_size_value))
                checksum_tcp = QTreeWidgetItem(tcp)
                checksum_tcp.setText(0, "Checksum:" + packet.tcp.checksum)
                ugrent_pointer = QTreeWidgetItem(tcp)
                ugrent_pointer.setText(0, "Urgent Pointer:" + packet.tcp.urgent_pointer)
                for kind in packet.tcp.kind:
                    options = QTreeWidgetItem(tcp)
                    options.setText(0, "Options:" + kind)
                sdl = QTreeWidgetItem(tcp)
                sdl.setText(0, "Segment Data Length:" + str(packet.tcp.segment_data_length))
                self.treeWidget.addTopLevelItem(tcp)
            elif packet.icmp:
                icmp = QTreeWidgetItem(self.treeWidget)
                icmp.setText(0, 'ICMP')
                type_icmp = QTreeWidgetItem(icmp)
                type_icmp.setText(0, "Type:" + packet.icmp.type_list[packet.icmp.type+packet.icmp.code]+'(0x'+packet.icmp.type+')')
                code_icmp = QTreeWidgetItem(icmp)
                code_icmp.setText(0, "Checksum:" + packet.icmp.code)
                checksum_icmp = QTreeWidgetItem(icmp)
                checksum_icmp.setText(0, "Checksum:" + packet.icmp.checksum)
                id_be_icmp = QTreeWidgetItem(icmp)
                id_be_icmp.setText(0, "Identifier BE:" + packet.icmp.identifier_be)
                id_le_icmp = QTreeWidgetItem(icmp)
                id_le_icmp.setText(0, "Identifier LE:" + packet.icmp.identifier_le)
                seq_num_be_icmp = QTreeWidgetItem(icmp)
                seq_num_be_icmp.setText(0, "Sequence Number BE:" + packet.icmp.sequence_number_be)
                seq_num_le_icmp = QTreeWidgetItem(icmp)
                seq_num_le_icmp.setText(0, "Sequence Number LE:" + packet.icmp.sequence_number_le)
                timestamp_icmp = QTreeWidgetItem(icmp)
                timestamp_icmp.setText(0, "Timestamp From ICMP Data:" + packet.icmp.timestamp_from_icmp_data)
                data_len_icmp = QTreeWidgetItem(icmp)
                data_len_icmp.setText(0, "Data Length:" + str(packet.icmp.data_length))
                self.treeWidget.addTopLevelItem(icmp)
            elif packet.udp:
                udp = QTreeWidgetItem(self.treeWidget)
                udp.setText(0, 'UDP')
                s_p_udp = QTreeWidgetItem(udp)
                s_p_udp.setText(0,"Source Port:"+str(packet.udp.source_port))
                d_p_udp = QTreeWidgetItem(udp)
                d_p_udp.setText(0, "Destination Port:"+str(packet.udp.destination_port))
                len_udp = QTreeWidgetItem(udp)
                len_udp.setText(0, "Length:"+str(packet.udp.length))
                checksum_udp = QTreeWidgetItem(udp)
                checksum_udp.setText(0, "Checksum:"+packet.udp.checksum)
                self.treeWidget.addTopLevelItem(udp)
                if packet.dns:
                    dns = QTreeWidgetItem(self.treeWidget)
                    dns.setText(0, 'DNS')
                    trans_id_dns = QTreeWidgetItem(dns)
                    trans_id_dns.setText(0, "Transaction Id:"+packet.dns.transaction_id)
                    flags_dns = QTreeWidgetItem(dns)
                    flags_dns.setText(0, "Flags:"+packet.dns.flags)
                    response_dns = QTreeWidgetItem(dns)
                    response_dns.setText(0, "Response:"+packet.dns.response)
                    questions_dns = QTreeWidgetItem(dns)
                    questions_dns.setText(0, "Questions:"+str(packet.dns.questions))
                    answer_rrs_dns = QTreeWidgetItem(dns)
                    answer_rrs_dns.setText(0, "Answer RRS:"+str(packet.dns.answer_rrs))
                    authority_rrs_dns = QTreeWidgetItem(dns)
                    authority_rrs_dns.setText(0, "Authority RRS:"+str(packet.dns.authority_rrs))
                    additional_rrs_dns = QTreeWidgetItem(dns)
                    additional_rrs_dns.setText(0, "Additional RRS:"+str(packet.dns.additional_rrs))
        elif packet.ipv6:
            ipv6 = QTreeWidgetItem(self.treeWidget)
            ipv6.setText(0, 'IPv6')
            version_ipv6 = QTreeWidgetItem(ipv6)
            version_ipv6.setText(0,"Version:"+packet.ipv6.version)
            traffic_class_ipv6 = QTreeWidgetItem(ipv6)
            traffic_class_ipv6.setText(0, "Traffic Class:" + packet.ipv6.traffic_class)
            dsc_ipv6 = QTreeWidgetItem(ipv6)
            dsc_ipv6.setText(0, "Differentiated Service Codepoint:" + str(packet.ipv6.differentiated_service_codepoint))
            ecn_ipv6 = QTreeWidgetItem(ipv6)
            ecn_ipv6.setText(0, "Explicit Congestion Notification:" + str(packet.ipv6.explicit_congestion_notification))
            fl_ipv6 = QTreeWidgetItem(ipv6)
            fl_ipv6.setText(0, "Flow Label:" + packet.ipv6.flow_label)
            pl_ipv6 = QTreeWidgetItem(ipv6)
            pl_ipv6.setText(0, "Payload Length:" + str(packet.ipv6.payload_length))
            np_ipv6 = QTreeWidgetItem(ipv6)
            np_ipv6.setText(0, "Protocol:" + packet.ipv6.next_proto)
            hl_ipv6 = QTreeWidgetItem(ipv6)
            hl_ipv6.setText(0, "Hop Limit:" + str(packet.ipv6.hop_limit))
            s_ipv6 = QTreeWidgetItem(ipv6)
            s_ipv6.setText(0, "Source:" + packet.ipv6.source)
            d_ipv6 = QTreeWidgetItem(ipv6)
            d_ipv6.setText(0, "Destination:" + packet.ipv6.destination)
            if packet.icmpv6:
                icmpv6 = QTreeWidgetItem(self.treeWidget)
                icmpv6.setText(0, 'ICMPv6')
                type_icmpv6 = QTreeWidgetItem(icmpv6)
                type_icmpv6.setText("Type:"+packet.icmpv6.info()+'('+str(packet.icmpv6.type)+')')
                code_icmpv6 = QTreeWidgetItem(icmpv6)
                code_icmpv6.setText("Code:"+str(packet.icmpv6.code))
                checksum_icmpv6 = QTreeWidgetItem(icmpv6)
                checksum_icmpv6.setText("Checksum:"+packet.icmpv6.checksum)
                chl_icmpv6 = QTreeWidgetItem(icmpv6)
                chl_icmpv6.setText("Cur Hop Limit:"+str(packet.icmpv6.cur_hop_limit))
                flags_icmpv6 = QTreeWidgetItem(icmpv6)
                flags_icmpv6.setText("Flags:"+packet.icmpv6.flags)
                rl_icmpv6 = QTreeWidgetItem(icmpv6)
                rl_icmpv6.setText("Router LifeTime:"+str(packet.icmpv6.router_lifetime))
                rt_icmpv6 = QTreeWidgetItem(icmpv6)
                rt_icmpv6.setText("Reachable Time:"+str(packet.icmpv6.reachable_time))
                rtt_icmpv6 = QTreeWidgetItem(icmpv6)
                rtt_icmpv6.setText("Retrans Time:"+str(packet.icmpv6.retrans_time))
                options_icmpv6 = QTreeWidgetItem(icmpv6)
                options_icmpv6.setText("Options:"+packet.icmpv6.options)


#将原生16进制报文显示出来
    def show_data(self,Item=None):
        if Item==None:
            return
        packet = self.pac_list[int(Item.row())]
        s = packet.stream_packet
        self.listWidget.clear()
        r = len(s)%32
        for i in range(len(s)//32):
            item = QListWidgetItem(self.listWidget)
            item.setText(' '.join(re.findall(r'.{2}',s[32*i:32*i+32]))+'\t'+toAscii(s[32*i:32*i+32]))
        if r:
            item = QListWidgetItem(self.listWidget)
            item.setText('{:47}'.format(' '.join(re.findall(r'.{2}',s[-r:])))+'\t'+toAscii(s[-r:]))

#跟踪TCP数据流，暂时只能在stop之后才能使用，动态使用存在问题
    def follow_tcp_stream(self):
        packets = []
        total_data = ''
        if self.pac_list[self.current_row].tcp:
            index = self.pac_list[self.current_row].tcp.stream_index
            self.tableWidget.setRowCount(0)
        else:
            return
        for packet in self.pac_list:
            if packet.tcp:
                if packet.tcp.stream_index == index:
                    packets.append(packet)
        self.pac_list = packets
        checksums = []
        packets_no_dup = []
        for packet in self.pac_list:
            if packet.tcp.checksum not in checksums:
                checksums.append(packet.tcp.checksum)
                packets_no_dup.append(packet)
        self.pac_list = packets_no_dup
        self.tableWidget.setRowCount(len(self.pac_list))
        for i in range(len(self.pac_list)):
            self.show_table(self.pac_list[i],i)
        print(len(self.pac_list))

#在跟踪TCP数据流之后使用
    def export_http_file(self):
        num = 0
        packets_1 = []
        packets_2 = []
        packets_1.append(self.pac_list[0])
        for packet in self.pac_list:
            if packet.tcp.source_port == self.pac_list[0].tcp.source_port:
                packets_1.append(packet)
            else:
                packets_2.append(packet)
        server = packets_2
        for packet in packets_2:
            if 'GET' in packet.ascii_data or 'POST' in packet.ascii_data:
                server = packets_1

        for j in range(len(server)):
            for k in range(j):
                if server[j].tcp.sequence_number < server[k].tcp.sequence_number:
                    server[j],server[k] = server[k],server[j]
        for packet in server:
            print(packet.tcp.sequence_number)
        i = 0
        files = []
        total_data = b''
        while i < len(server):
            if 'HTTP/' in server[i].ascii_data:
                total_data = server[i].tcp.actual_data
                i += 1
                while i < len(server) and 'HTTP/' not in server[i].ascii_data and server[i].tcp.actual_data != b'':
                    total_data = total_data + server[i].tcp.actual_data
                    i += 1
                files.append(total_data)
            else:
                i += 1
                print(i)

        for file in files:
            index = file.index(b'\x0d\x0a\x0d\x0a') + 4
            data = file[index:]
            if b'gzip' in file:
                try:
                    index = file.index(b'\x1f\x8b')
                    data = file[index:]
                    if b'\x0d\x0a' in data:
                        index_final = data.index(b'\x0d\x0a')
                        data = data[:index_final]
                    data = gzip.decompress(data)
                except:
                    print(data)
                    print('can\'t decode')
                    continue
            if b'text/html' in file:
                outfile = open("file" + str(num) + ".html", 'wb')
                num += 1
                outfile.write(data)
                outfile.close()
            elif b'text/css' in file:
                outfile = open("file" + str(num) + ".css", 'wb')
                num += 1
                outfile.write(data)
                outfile.close()
            elif b'application/x-javascript' in file:
                outfile = open("file" + str(num) + ".js", 'wb')
                num += 1
                outfile.write(data)
                outfile.close()
            elif b'application/json' in file:
                outfile = open("file" + str(num) + ".json", 'wb')
                num += 1
                outfile.write(data)
                outfile.close()
            elif b'image/jpeg' in file:
                outfile = open("file" + str(num) + ".jpeg", 'wb')
                num += 1
                outfile.write(data)
                outfile.close()
            elif b'image/png' in file:
                outfile = open("file" + str(num) + ".png", 'wb')
                num += 1
                outfile.write(data)
                outfile.close()
            elif b'image/gif' in file:
                outfile = open("file" + str(num) + ".gif", 'wb')
                num += 1
                outfile.write(data)
                outfile.close()
            else:
                continue

    def export_ftp_file(self):
        num = 0
        packets_1 = []
        packets_2 = []
        packets_1.append(self.pac_list[0])
        for packet in self.pac_list:
            if packet.tcp.source_port == self.pac_list[0].tcp.source_port:
                packets_1.append(packet)
            else:
                packets_2.append(packet)
        server = packets_2
        client = packets_1

        for packet in packets_1:
            if int(packet.tcp.flags[4]) and int(packet.tcp.flags[7]):
                server = packets_1
                client = packets_2
        for j in range(len(server)):
            for k in range(j):
                if server[j].tcp.sequence_number < server[k].tcp.sequence_number:
                    server[j], server[k] = server[k], server[j]
        for packet in server:
            print(packet.tcp.sequence_number)
        total_data = b''
        file_path = b''
        filename = ''
        i = 0
        for packet in client:
            if b'RETR' in packet.tcp.actual_data:
                file_path = packet.tcp.actual_data[5:-2]
                filename = hexstr2unicode(bytes.hex(file_path)).split('/')[-1]
        while file_path not in server[i]:
            i = i + 1
        i = i + 1
        while i < len(server):
            total_data = total_data + server[i].tcp.actual_data
            i = i + 1
        outfile = open(filename, 'wb')
        outfile.write(total_data)
        outfile.close()


    def save_packets(self):
        file_path,type = QFileDialog.getSaveFileName(self, "save file", "","Text Files (*.txt)")
        saved_file = open(file_path+".txt", 'a')
        for packet in self.pac_list:
            if packet.tcp:
                saved_file.write(toAscii(bytes.hex(packet.tcp.actual_data)))
        saved_file.close()

    def restart(self):
        self.total_pac_list = []
        self.pac_list = []
        self.number = 0
        self.start_time = 0
        self.thread.clear()
        self.thread.start()


    #显示之外的后端主进程，主要用于抓包和存包，并将得到的包传递给mywindow显示和处理进程
class SniffThread(QThread):
    packets = []
    numbers = 0
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sniff_signal = pyqtSignal(type([]))
    start_signal = pyqtSignal(float)

    def __init__(self,interface='wlp3s0',parent=None):
        super().__init__(parent)
        self.interface = interface

    def run(self):
        self.start_signal.emit(time.time())
        self.sniffer.bind((self.interface, 0))
        while True:
            packet = self.sniffer.recvfrom(65565)
            data = packet[0]
            try:
                p = Packet(str2hex(data))
                self.packets.append(p)
            except:
                print('error')
            if len(self.packets) > self.numbers:
                self.sniff_signal.emit(self.packets)
            self.numbers = len(self.packets)

    def clear(self):
        self.packets = []
        self.numbers = 0


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    myshow = mywindow()
    myshow.show()
    app.exec_()