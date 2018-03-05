import sys
import socket
import struct
import textwrap
import binascii
import datetime




try:
	output_file = sys.argv[1]
except:
	output_file = 'default_output'


f_out = open(output_file,"w") 
f_ip = open("iplist.txt","r")

try:
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except:
	print("Could not create socket object ")


#Unpack ethernet frame
def ethernet_frame(data):
	dest_mac, src_mac, proto  = struct.unpack('! 6s 6s H', data[:14])
	return dest_mac,src_mac,socket.htons(proto),data[14:]



#List ip addresses for the further analisy

ip_list = f_ip.read().split(",");

# Get mac address from the frame

def get_mac_addr(mac):
	bytes_str = map('{:02x}'.format,mac)
	return '-'.join(bytes_str).upper()

# Get ip address from the packet

def get_ip(data):
	ip =  struct.unpack('!BBHHHBBH4s4s',data[:20])
	return ip,data[20:]

#Get udp data from the segment

def get_udp(data):
	udp = struct.unpack('!HHH2s',data[:8])
	return udp,data[8:]

# Get gtp version 1/2

def get_gtp_version(data):
	flags = struct.unpack('!B',data[:1])
	return flags,data[1:]

# Get message type Request/Response from GTP

def get_gtp_type(data):
	gtp = struct.unpack('!sss',data[:3])
	return gtp

# Get message type Request/Response from GTPv2

def get_gtp_type_lte(data):
	gtp = struct.unpack('!BBB',data[:3])
	return gtp

# Get  ie type from GTPv2 message

def get_ie_type_gtpv2(data):
	ie = struct.unpack('!BBHB',data[:5])
	return ie,data[5:]


# Get ie type depending on a position

def get_ie_type(data,pos):
	ie = struct.unpack('!BH',data[pos:3+pos])
	return ie,data[pos+3:]


def get_gtp(data):
	gtp = struct.unpack('!BsH4s2sss9s',data[:21])
	return gtp,data[21:]


def get_gtp_session(data):
	gtp = struct.unpack('!BsH4s3sB3s9s',data[:24])
	return gtp,data[24:]


def get_gtp_session_header(data):
	gtp = struct.unpack('!BsH4s3s',data[:11])
	return gtp,data[11:]

def get_gtp_session_response(data):
	gtp = struct.unpack('!BsH4s3sBBBBBBB',data[:18])
	return gtp,data[18:]

def get_gtp_resp(data):
	gtp = struct.unpack('!BsH4s2s2ssB',data[:14])
	return gtp,data[14:]



def convert_imsi_hex(imsi):
	element = 2
	readable_imsi = ""
	while element < len(imsi)-1:
		readable_imsi +=imsi[element+1]
		readable_imsi +=imsi[element]
		element +=2
	return readable_imsi[:15]
		
		

while True:
	result = s.recv(65466)
	src_mac,dest_mac,proto,raw_data = ethernet_frame(result)

	ip,data = get_ip(raw_data)

	if ip[6] == 17:

		if socket.inet_ntoa(ip[8]) in ip_list or socket.inet_ntoa(ip[9]) in ip_list:
			udp,data = get_udp(data)
			flags,d = get_gtp_version(data)
			flag = flags[0] >> 5

			if flag == 1:
				gtp_msg_type = get_gtp_type(data)
				if gtp_msg_type[1] == b'\x10':
					
					
					gtp,data = get_gtp(data)
					
					f_out.write("{'Timestamp':'" + str(datetime.datetime.now())+"'")
					f_out.write(",'Type':'Create PDP context request'")
					f_out.write(",'Source':'" + socket.inet_ntoa(ip[8])+"'")
					f_out.write(",'Destination':'"+socket.inet_ntoa(ip[9])+"'")
					#f_out.write(",'Length':'"+str(gtp[2])+"'")
					#f_out.write(",'TEID':'"+str(gtp[3])+"'")
					f_out.write(",'seqid':'"+"".join("{:02x}".format(c) for c in gtp[4])+"'")
					imsi_hex =  "".join("{:02x}".format(i) for i in gtp[7])
					f_out.write(",'imsi':'"+ convert_imsi_hex(imsi_hex)+"'")	
					f_out.write("}")
					f_out.write("\n")
				elif gtp_msg_type[1] == b'\x11':
					
					gtp,data = get_gtp_resp(data)
				
					f_out.write("{'Timestamp':'" + str(datetime.datetime.now())+"'")
					f_out.write(",'Type':'Create PDP context response'")
					f_out.write(",'Source':'" + socket.inet_ntoa(ip[8])+"'")
					f_out.write(",'Destination':'"+socket.inet_ntoa(ip[9])+"'")
					#f_out.write(",'Length':"+str(gtp[2])+"'")
					#f_out.write(",'TEID': "+str(gtp[3])+"'")
					f_out.write(",'seqid':'"+"".join("{:02x}".format(c) for c in gtp[4])+"'")
					f_out.write(",'cause_code':'"+str(gtp[7])+"'")
					f_out.write("}")
					f_out.write("\n")
			elif flag == 2:
				gtp_msg_type_lte  = get_gtp_type_lte(data)
				
				if gtp_msg_type_lte[1] == 33 : 
					f_out.write ("{'Timestamp':'" + str(datetime.datetime.now())+"'")
					f_out.write(",'Type':'Create Session Response'")
					gtp,data = get_gtp_session_response(data)
					f_out.write(",'Source':'" + socket.inet_ntoa(ip[8])+"'")
					f_out.write(",'Destination':'"+socket.inet_ntoa(ip[9])+"'")
					#f_out.write(",'Length':'"+str(gtp[2])+"'")
					#f_out.write(",'TEID':'"+str(gtp[3])+"'")
					f_out.write(",'seqid':'"+"".join("{:02x}".format(c) for c in gtp[4])+"'")
					f_out.write(",'cause_code':'"+str(gtp[10])+"'")
					f_out.write("}")
					f_out.write("\n")
				elif gtp_msg_type_lte[1] == 32 :
					header,body = get_gtp_session_header(data)
					ie,rest = get_ie_type_gtpv2(body)
					
					if ie[1] == 1:
						f_out.write ("{'Timestamp':'" + str(datetime.datetime.now())+"'")
						f_out.write (",'Type':'Create Session Request'") 

						gtp,data = get_gtp_session(data)
						f_out.write(",'Source':'" + socket.inet_ntoa(ip[8])+"'")
						f_out.write(",'Destination':'"+socket.inet_ntoa(ip[9])+"'")
						#f_out.write(",'Length':'"+str(gtp[2])+"'")
						#f_out.write(",'TEID':'"+str(gtp[3])+"'")
						f_out.write(",'seqid':'"+"".join("{:02x}".format(c) for c in gtp[4])+"'")
						
						imsi_hex =  "".join("{:02x}".format(i) for i in gtp[7])
						f_out.write(",'imsi':'"+ convert_imsi_hex(imsi_hex)+"'")
						f_out.write("}")
						f_out.write("\n")
					elif ie[1] == 82:
						f_out.write ("{'Timestamp':'" + str(datetime.datetime.now())+"'")
						f_out.write (",'Type':'Create Session Request'")
						gtp,data1 = get_gtp_session(data)
						f_out.write(",'Source':'" + socket.inet_ntoa(ip[8])+"'")
						f_out.write(",'Destination': '"+socket.inet_ntoa(ip[9])+"'")
						#f_out.write(",'Length': '"+str(gtp[2])+"'")
						#f_out.write(",'TEID': '"+str(gtp[3])+"'")
						f_out.write(",'seqid':'"+"".join("{:02x}".format(c) for c in gtp[4])+"'")
						ie,data = get_ie_type(data,30)
						ie,data = get_ie_type(data,ie[1]+1)
						imsi_hex =  "".join("{:02x}".format(i) for i in data[0:9])	
						f_out.write(",'imsi':'"+ convert_imsi_hex(imsi_hex)+"'")
						f_out.write("}")
						f_out.write("\n")
