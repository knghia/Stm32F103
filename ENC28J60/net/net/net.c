#include "main.h"

u16 source_port = 80;
u08 mac_addr[6] = {0};
u08 ip_addr[4] = {0};

u08 mac_pc[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
u08 ip_pc[4] = {192,168,137,10};

extern void net_init(u08 mymac[6], u08 myip[4], u16 myport){
	u08 debug = 0xFF;
	/* 1. INIT ENC28J60 */
	enc28j60Init(mymac);  
	debug = enc28j60getrev();  
	enc28j60PhyWrite(PHLCON, 0x476);
	// change clkout from 6.25MHz to 12.5MHz   
	enc28j60clkout(2);
	
	/* 1. INIT NET */
	source_port = myport;
	copy_arr(mac_addr, mymac, 6);
	copy_arr(ip_addr, myip, 4);
	
	net_arp_get_mac_ip_pc(mac_pc, ip_pc, 1000);
}

#define BUFFER_SIZE 1500
volatile u08 rx_buf[BUFFER_SIZE+1] = {0};
volatile u16 plen = 0;

extern bool net_analysis(void){
	#ifdef DEBUG
		static u08 index = 0;
	#endif
	ProtocolIP protocol = NONE;
	plen = 0;
	plen = enc28j60PacketReceive(BUFFER_SIZE, (u08*)rx_buf);
	if (plen == 0){ 
		return false;
	}
	else{
		protocol = NONE;
		rx_buf[plen] = '\0';
		if(((rx_buf[I_ARP_ETHERNET_TYPE_H]<<8) + \
			rx_buf[I_ARP_ETHERNET_TYPE_L]) == ARP_ETHERNET_TYPE){
			protocol = ARP;
		}
		else if(rx_buf[I_IPV4_PROTOCOL] == IPV4_PROTOCOL_ICMP){
			protocol = ICMP;
		}
		else if(rx_buf[I_IPV4_PROTOCOL] == IPV4_PROTOCOL_UDP){
			protocol = UDP;
		}
		else if(rx_buf[I_IPV4_PROTOCOL] == IPV4_PROTOCOL_TCP){
			protocol = TCP_IP;
		}
		
		switch (protocol){
			case ARP:{
				if (net_arp_check_broadcast((u08*)rx_buf, plen) == true){
					net_arp_reply((u08*)rx_buf, plen);
					#ifdef DEBUG
					index+=1;
					printf("arp %d \r\n", index);
					#endif
					return true;
				}
				net_arp_reply((u08*)rx_buf, plen);
				break;
			}
			case ICMP:{
				if (net_icmp_check((u08*)rx_buf, plen) == true){
					net_icmp_reply((u08*)rx_buf, plen);
					#ifdef DEBUG
					index+=1;
					printf("icmp %d \r\n", index);
					#endif
					return true;
				}
				break;
			}
			case UDP:{
				if (net_udp_check((u08*)rx_buf, plen) == true){
					net_udp_reply((u08*)rx_buf, plen);
					#ifdef DEBUG
					index+=1;
					printf("udp %d \r\n", index);
					#endif
					return true;
				}
				break;
			}
			case TCP_IP:{
				if (net_tcp_ip_check((u08*)rx_buf, plen) == true){
					net_tcp_ip_reply((u08*)rx_buf, plen);
					return true;
				}
				break;
			}
			default:
				break;
		}
		return false;
	}
}

extern bool net_arp_check_broadcast(u08* ping, u16 len){
	if (len<41){
		return false;
	}
	u08 mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	if(!com_arr(&ping[I_ARP_MAC_DEST], mac, 6)){
		return false;
	}
	if(!com_arr(&ping[I_ARP_IP_TARGET], ip_addr, 4)){
		return false;
	}
	/* check  protocol IPv4 - 0x0800*/
	if(((ping[I_ARP_PROTOCOL_TYPE_H]<<8) + ping[I_ARP_PROTOCOL_TYPE_L]) != IPV4_ETHERNET_TYPE){
		return false;
	}
	/* check  protocol IPv4 - 0x0806*/
	if(((ping[I_ARP_ETHERNET_TYPE_H]<<8) + ping[I_ARP_ETHERNET_TYPE_L]) != ARP_ETHERNET_TYPE){
		return false;
	}
	return true;
}

extern void net_arp_reply(u08* ping, u16 len){
	ARP_Frame* arp_data = (ARP_Frame*)ping;
	copy_arr(arp_data->MAC_dest, &ping[I_ARP_MAC_SENDER], 0);
	copy_arr(arp_data->MAC_source, mac_addr, 6);
	arp_data->Opcode = swap16(ARP_OPCODE_REPLY);
	copy_arr(arp_data->MAC_sender, mac_addr, 6);
	copy_arr(arp_data->IP_sender, ip_addr, 4);
	copy_arr(arp_data->MAC_target, &ping[I_AdRP_MAC_SENDER], 6);
	copy_arr(arp_data->IP_target, &ping[I_ARP_MAC_TARGET], 4);
	enc28j60PacketSend(ARP_PACKET_LEN, (u08*)arp_data);
}

extern bool net_arp_get_mac_ip_pc(u08 mac_target[6], u08 ip_target[4], u16 timeout){
	u08 data[100] = {0};
	u16 len = 0;
	ARP_Frame arp_struct;
	
	copy_arr(arp_struct.MAC_dest, mac_target, 6);
	copy_arr(arp_struct.MAC_source, mac_addr, 6);
	
	arp_struct.Ethernet_type = swap16(ARP_ETHERNET_TYPE);
	arp_struct.Hardwave_type = swap16(ARP_HARDWAVE_TYPE);
	arp_struct.Protocol_type = swap16(ARP_PROTOCOL_TYPE);
	arp_struct.Size = swap16(ARP_SIZE);
	arp_struct.Opcode = swap16(ARP_OPCODE_REQUEST);
	
	copy_arr(arp_struct.MAC_sender, mac_addr, 6);
	copy_arr(arp_struct.IP_sender, ip_addr, 4);
	
	mac_target[0] = 0x00;
	mac_target[1] = 0x00;
	mac_target[2] = 0x00;
	
	mac_target[3] = 0x00;
	mac_target[4] = 0x00;
	mac_target[5] = 0x00;

	copy_arr(arp_struct.MAC_target, mac_target, 6);
	copy_arr(arp_struct.IP_target, ip_target, 4);

	while(timeout--){
		enc28j60PacketSend(ARP_PACKET_LEN, (u08 *)&arp_struct);
		delay_ms(500);
		len = enc28j60PacketReceive(BUFFER_SIZE, data); 
		if (len >= 42){
			/* ARP OPCODE request */
			u16 arp_opcode = (data[I_ARP_OPCODE_H]<<8) + data[I_ARP_OPCODE_L];
			if(arp_opcode == ARP_OPCODE_REPLY){
				/* compare MAC source */
				if(com_arr(&data[I_ARP_MAC_TARGET], (u08*)mac_addr, 6)){
					/* compare IP source */
					if(com_arr(&data[I_ARP_IP_TARGET], (u08*)ip_addr, 4)){
						copy_arr(mac_target, &data[I_ARP_MAC_SENDER], 6);
						#ifdef DEBUG
							printf("MAC: %02x %02x %02x %02x %02x %02x\r\n", \
						mac_target[0], mac_target[1], mac_target[2], \
						mac_target[3], mac_target[4], mac_target[5]);
						#endif
						return true;
					}
				}
			}
		}
		if (timeout == 0){
			break;
		}
	}
	return false;
}

extern bool net_icmp_check(u08* ping, u16 len){
	if (len<41){
		return false;
	}
	/* compare mac addr */
	if (!com_arr(&ping[I_IPV4_MAC_SOURCE], mac_addr, 6)){
			return false;
	}
	/* compare mac pc */
	if (!com_arr(&ping[I_IPV4_MAC_DEST], mac_pc, 6)){
			return false;
	}
	/* compare ip pc */
	if (!com_arr(&ping[I_IPV4_SOURCE_IP], ip_pc, 4)){
			return false;
	}
	/* compare ip addr */
	if (!com_arr(&ping[I_IPV4_DEST_IP], ip_addr, 4)){
			return false;
	}
	/* compare ICMP request */
	if (!(ping[I_ICMP_TYPE] == 0x08)){
			return false;
	}
	/* check crc */
	uint16_t real_crc, crc = 0;
	real_crc = ping[I_ICMP_CHECKSUM_H] + (ping[I_ICMP_CHECKSUM_L]<<8);
	ping[I_ICMP_CHECKSUM_H] = 0;
	ping[I_ICMP_CHECKSUM_L] = 0;
	crc = icmp_checksum(&ping[I_ICMP_TYPE], ICMP_SIZE+ len-IPV4_ICMP_SIZE);
	if(real_crc != crc){
		return false;
	}
	if (((ping[I_IPV4_ETHERNET_TYPE]<<8)+ ping[I_IPV4_ETHERNET_TYPE+1]) != IPV4_ETHERNET_TYPE){
		return false;
	}
	/* ICMP protocol : 0x01 */
	if (ping[I_IPV4_PROTOCOL] != IPV4_PROTOCOL_ICMP){
		return false;
	}
	return true;
}

extern void net_icmp_reply(u08* ping, u16 len){
	ICMP_Frame* icmp_struct = (ICMP_Frame*)ping;
	copy_arr(icmp_struct->MAC_dest, &ping[6], 0);
	copy_arr(icmp_struct->MAC_source,  &ping[0], 6);
	icmp_struct->CheckSum = 0x0000;
	icmp_struct->CheckSum = ipv4_checksum((u08 *)icmp_struct->Header_length, IPV4_SIZE);
	copy_arr(icmp_struct->SourceIP, ip_addr, 4);
	copy_arr(icmp_struct->DestIP, ip_pc, 4);
	icmp_struct->ICMP_Checksum = 0x0000;
	copy_arr(icmp_struct->ICMP_Data, &ping[IPV4_ICMP_SIZE], len-IPV4_ICMP_SIZE);
	icmp_struct->ICMP_Checksum = icmp_checksum((u08*)icmp_struct->ICMP_Type, ICMP_SIZE+ len-IPV4_ICMP_SIZE);
	enc28j60PacketSend(len, (u08*)icmp_struct);
}

extern bool net_udp_check(u08* request, u16 len){
	if (len<41){
		return false;
	}
	/* compare mac addr */
	if (!com_arr(&request[I_IPV4_MAC_SOURCE], mac_addr, 6)){
			return false;
	}
	/* compare mac pc */
	if (!com_arr(&request[I_IPV4_MAC_DEST], mac_pc, 6)){
			return false;
	}
	/* compare ip pc */
	if (!com_arr(&request[I_IPV4_SOURCE_IP], ip_pc, 4)){
			return false;
	}
	/* compare ip addr */
	if (!com_arr(&request[I_IPV4_DEST_IP], ip_addr, 4)){
			return false;
	}
	/* compare port source */
	u16 port = (request[I_UDP_DST_PORT_H]<<8) + request[I_UDP_DST_PORT_L];
	if (port != source_port){
			return false;
	}
	/* check crc */
	u16 real_crc, crc, crc_len = 0;
	real_crc = request[I_UDP_CHECKSUM_H] + (request[I_UDP_CHECKSUM_L]<<8);
	request[I_UDP_CHECKSUM_H] = 0;
	request[I_UDP_CHECKSUM_L] = 0;
	crc_len = (request[I_UDP_LEN_H]<<8) + request[I_UDP_LEN_L] + 8;
	crc = udp_checksum(&request[I_IPV4_SOURCE_IP], crc_len);
	
	if (real_crc != crc){
		return false;
	}
	
	if (((request[I_IPV4_ETHERNET_TYPE]<<8)+request[I_IPV4_ETHERNET_TYPE+1]) != IPV4_ETHERNET_TYPE){
		return false;
	}
	/* UDP protocol : 0x11 */
	if (request[I_IPV4_PROTOCOL] != IPV4_PROTOCOL_UDP){
		return false;
	}
	return true;
}

extern void net_udp_reply(u08* ping, u16 len){
	static u08 udp_data_request[50];
	static u08 udp_len = 0;
	
	udp_len = (ping[I_UDP_LEN_H]<<8) + ping[I_UDP_LEN_L];
	copy_arr(udp_data_request, &ping[I_UDP_DATA], udp_len);
	
	if (com_arr(udp_data_request, (u08*)"LED13=HIGH\r\n", 12)){
		net_udp_handle(0);
		net_udp_request(ping, (u08*)"LED13=HIGH\r\n", 12);
	}
	else if (com_arr(udp_data_request, (u08*)"LED13=LOW\r\n", 11)){
		net_udp_handle(1);
		net_udp_request(ping, (u08*)"LED13=LOW\r\n", 11);
	}
	else{
		net_udp_handle(2);
		net_udp_request(ping, (u08*)"INCORRECT\r\n", 11);
	}
}

extern void net_udp_request(u08* request, u08* data, u16 len_of_data){
	UDP_Frame* udp_struct = (UDP_Frame*)request;
	copy_arr(udp_struct->MAC_dest, &request[6], 0);
	copy_arr(udp_struct->MAC_source, &request[0], 6);
	
	udp_struct->CheckSum = 0x0000;
	udp_struct->CheckSum = ipv4_checksum((u08 *)udp_struct->Header_length, IPV4_SIZE);
	copy_arr(udp_struct->SourceIP, ip_addr, 4);
	copy_arr(udp_struct->DestIP, ip_pc, 4);
	
	udp_struct->UDP_Source_Port = swap16(source_port);
	udp_struct->UDP_Dest_Port = swap16((request[I_UDP_SRC_PORT_H]<<8) + request[I_UDP_SRC_PORT_L]);;
	udp_struct->UDP_Length = swap16(UDP_SIZE + len_of_data);
	copy_arr(udp_struct->UDP_Data, data, len_of_data);
	
	/* check sum */
	udp_struct->UDP_Checksum = 0x0000;
	udp_struct->UDP_Checksum = udp_checksum((u08*)udp_struct->SourceIP, UDP_SIZE + len_of_data + 8);
	
	enc28j60PacketSend(I_UDP_DATA + len_of_data, (u08*)udp_struct);	
}

extern bool net_tcp_ip_check(u08* request, u16 len){
	if (len<41){
		return false;
	}
	/* compare mac addr */
	if (!com_arr(&request[I_IPV4_MAC_SOURCE], mac_addr, 6)){
			return false;
	}
	/* compare ip addr */
	if (!com_arr(&request[I_IPV4_DEST_IP], ip_addr, 4)){
			return false;
	}
	/* compare port source */
	u16 port = (request[I_TCP_DST_PORT_H]<<8) + request[I_TCP_DST_PORT_L];
	if (port != source_port){
			return false;
	}
	if (((request[I_IPV4_ETHERNET_TYPE]<<8)+request[I_IPV4_ETHERNET_TYPE+1]) != IPV4_ETHERNET_TYPE){
		return false;
	}
	/* TCP protocol : 0x06 */
	if (request[I_IPV4_PROTOCOL] != IPV4_PROTOCOL_TCP){
		return false;
	}
	return true;
}

<<<<<<< HEAD
void printf_debug(u08* data, u16 len){
	for(u08 i=0; i<len; i++){
		if (i%16 == 0 && i>0){
			printf("\r\n");
		}
		printf("%02x ", data[i]);
	}		
	printf("\r\n");
}

volatile u32 seq_num_local, ack_num_local = 0;

void net_tcp_ip_reply_syn(u08* request, u16 len){
	u32 total_len = 0;
	TCP_Frame tcp_struct;
	copy_arr(tcp_struct.MAC_dest, &request[6], 6);
	copy_arr(tcp_struct.MAC_source, &request[0], 6);
	
	tcp_struct.Ethernet_type = swap16(IPV4_ETHERNET_TYPE);
	
	tcp_struct.Header_length = IPV4_HEADER_LENGTH;
	tcp_struct.Services = IPV4_SERVICES;
	total_len = (request[I_IPV4_TOTAL_LENGTH_H]<<8) + request[I_IPV4_TOTAL_LENGTH_L];
	tcp_struct.TotalLength = swap16(total_len);
	tcp_struct.Identification = swap16((request[I_IPV4_IDENTIFI_H]<<8) + request[I_IPV4_IDENTIFI_L]);
	tcp_struct.Flag = swap16(IPV4_FLAG);
	tcp_struct.TimeToLive = IPV4_TIME_TO_LIVE;
	tcp_struct.Protocol = IPV4_PROTOCOL_TCP;
	tcp_struct.CheckSum = 0x0000;
	tcp_struct.CheckSum = ipv4_checksum((u08 *)&tcp_struct.Header_length, IPV4_SIZE);
	copy_arr(tcp_struct.SourceIP, ip_addr, 4);
	copy_arr(tcp_struct.DestIP, ip_pc, 4);
	
	tcp_struct.TCP_Source_Port = swap16((request[I_TCP_DST_PORT_H]<<8) + request[I_TCP_DST_PORT_L]);
	tcp_struct.TCP_Dest_Port = swap16((request[I_TCP_SRC_PORT_H]<<8) + request[I_TCP_SRC_PORT_L]);
	
	seq_num_local =  (request[I_TCP_SEQ_NUM]<<24) + (request[I_TCP_SEQ_NUM+1]<<16) + \
	(request[I_TCP_SEQ_NUM+2]<<8) + request[I_TCP_SEQ_NUM+3] + 1;
	ack_num_local = 0x08101997;
	
	tcp_struct.TCP_Seq_Number = swap32(ack_num_local);
	tcp_struct.TCP_Ack_Number = swap32(seq_num_local);
	
	tcp_struct.TCP_Data_Offset = request[I_TCP_FLAGS_H];
  tcp_struct.TCP_Flags = TCP_FLAGS_SYN|TCP_FLAGS_ACK;
  tcp_struct.TCP_Window = swap16((request[I_TCP_WIN_H]<<8) + request[I_TCP_WIN_L]);
  tcp_struct.TCP_Checksums = 0x0000;
  tcp_struct.TCP_Urgent_Pointer = 0;
	
	copy_arr(tcp_struct.TCP_Data, &request[I_TCP_OPT_MSS_KIND], 12);
=======
volatile u32 seq_num_local, ack_num_local = 0;
>>>>>>> 7e059aa7f3496fc8bdc11f9b489b41d7c29ea1df

void net_tcp_ip_reply_syn(u08* request, u16 len){
	u32 total_len = 0;
	TCP_Frame* tcp_struct = (TCP_Frame*)request;
	copy_arr(tcp_struct->MAC_dest, &request[6], 0);
	copy_arr(tcp_struct->MAC_source, &request[0], 6);

	tcp_struct->CheckSum = 0x0000;
	tcp_struct->CheckSum = ipv4_checksum((u08 *)tcp_struct->Header_length, IPV4_SIZE);
	copy_arr(tcp_struct->SourceIP, ip_addr, 4);
	copy_arr(tcp_struct->DestIP, ip_pc, 4);
	
	tcp_struct->TCP_Source_Port = swap16((request[I_TCP_DST_PORT_H]<<8) + request[I_TCP_DST_PORT_L]);
	tcp_struct->TCP_Dest_Port = swap16((request[I_TCP_SRC_PORT_H]<<8) + request[I_TCP_SRC_PORT_L]);
	
	seq_num_local =  (request[I_TCP_SEQ_NUM]<<24) + (request[I_TCP_SEQ_NUM+1]<<16) + \
	(request[I_TCP_SEQ_NUM+2]<<8) + request[I_TCP_SEQ_NUM+3] + 1;
	
	tcp_struct->TCP_Seq_Number = swap32(0x08101997);
	tcp_struct->TCP_Ack_Number = swap32(seq_num_local);
	
	tcp_struct->TCP_Data_Offset = request[I_TCP_FLAGS_H];
  	tcp_struct->TCP_Flags = TCP_FLAGS_SYN|TCP_FLAGS_ACK;
	/* check sum */
<<<<<<< HEAD
	tcp_struct.TCP_Checksums = tcp_checksum((u08*)&tcp_struct.SourceIP, total_len - 20 +8);
	enc28j60PacketSend(len, (u08*)&tcp_struct);
	
	printf_debug((u08*)&tcp_struct, len);
	
=======
	total_len = (request[I_IPV4_TOTAL_LENGTH_H]<<8) + request[I_IPV4_TOTAL_LENGTH_L];
	tcp_struct->TCP_Checksums = 0x0000;
	tcp_struct->TCP_Checksums = tcp_checksum((u08*)tcp_struct->SourceIP, total_len - 20 +8);
	enc28j60PacketSend(len, (u08*)tcp_struct);
>>>>>>> 7e059aa7f3496fc8bdc11f9b489b41d7c29ea1df
}

bool net_tcp_ip_reply_ack(u08* request, u16 len){
	u32 seq_num, ack_num = 0;
	seq_num =  (request[I_TCP_SEQ_NUM]<<24) + (request[I_TCP_SEQ_NUM+1]<<16) + \
	(request[I_TCP_SEQ_NUM+2]<<8) + request[I_TCP_SEQ_NUM+3];

	ack_num =  (request[I_TCP_ACK_NUM]<<24) + (request[I_TCP_ACK_NUM+1]<<16) + \
	(request[I_TCP_ACK_NUM+2]<<8) + request[I_TCP_ACK_NUM+3];

	if (seq_num == ack_num_local && ack_num == (seq_num_local+1)){
		return true;
	}
	return false;
}

void net_tcp_ip_reply_fin_ack(u08* request, u16 len){
	u32 total_len = 0;
	TCP_Frame* tcp_struct = (TCP_Frame*)request;
	copy_arr(tcp_struct->MAC_dest, &request[6], 0);
	copy_arr(tcp_struct->MAC_source, &request[0], 6);

	tcp_struct->CheckSum = 0x0000;
	tcp_struct->CheckSum = ipv4_checksum((u08 *)tcp_struct->Header_length, IPV4_SIZE);
	copy_arr(tcp_struct->SourceIP, ip_addr, 4);
	copy_arr(tcp_struct->DestIP, ip_pc, 4);
	
	tcp_struct->TCP_Source_Port = swap16((request[I_TCP_DST_PORT_H]<<8) + request[I_TCP_DST_PORT_L]);
	tcp_struct->TCP_Dest_Port = swap16((request[I_TCP_SRC_PORT_H]<<8) + request[I_TCP_SRC_PORT_L]);
	
	seq_num_local =  (request[I_TCP_SEQ_NUM]<<24) + (request[I_TCP_SEQ_NUM+1]<<16) + \
	(request[I_TCP_SEQ_NUM+2]<<8) + request[I_TCP_SEQ_NUM+3];
	
<<<<<<< HEAD
	tcp_struct->TCP_Seq_Number = swap32(ack_num_local);
	tcp_struct->TCP_Ack_Number = swap32(seq_num_local);

  tcp_struct->TCP_Flags = TCP_FLAGS_ACK;
	/* check sum */
	total_len = (request[I_IPV4_TOTAL_LENGTH_H]<<8) + request[I_IPV4_TOTAL_LENGTH_L];
  tcp_struct->TCP_Checksums = 0x0000;
	tcp_struct->TCP_Checksums = tcp_checksum((u08*)tcp_struct->SourceIP, total_len - 20 +8);
	enc28j60PacketSend(len, (u08*)tcp_struct);
	
=======
	tcp_struct->TCP_Seq_Number = swap32(0x08101997);
	tcp_struct->TCP_Ack_Number = swap32(seq_num_local);

  	tcp_struct->TCP_Flags = TCP_FLAGS_ACK;
	/* check sum */
	total_len = (request[I_IPV4_TOTAL_LENGTH_H]<<8) + request[I_IPV4_TOTAL_LENGTH_L];
  	tcp_struct->TCP_Checksums = 0x0000;
	tcp_struct->TCP_Checksums = tcp_checksum((u08*)tcp_struct->SourceIP, total_len - 20 +8);
	enc28j60PacketSend(len, (u08*)tcp_struct);
>>>>>>> 7e059aa7f3496fc8bdc11f9b489b41d7c29ea1df
}

typedef enum{
	TCP_SYN_NONE = 0,
	TCP_SYN_SYN_1 = 1,
	TCP_SYN_SYN_2 = 2,
	TCP_SYN_END_1 = 3,
	TCP_SYN_END_2 = 4
}TCP_Step;

extern void net_tcp_ip_reply(u08* request, u16 len){
<<<<<<< HEAD
	static TCP_Step tcp_step = TCP_SYN_NONE;
=======
	static TCP_Step
>>>>>>> 7e059aa7f3496fc8bdc11f9b489b41d7c29ea1df
	static bool threeway_handshake = false;
	/* Check SYN : step 1*/	
	u08 syn = request[I_TCP_FLAGS_L];
	if ((syn&TCP_FLAGS_SYN) != 0 && (syn&TCP_FLAGS_ACK) == 0){
		net_tcp_ip_reply_syn(request, len);
<<<<<<< HEAD
		tcp_step = TCP_SYN_SYN_1;
		return;
	}
	/* Check SYN : step 3*/	
	if ((syn&TCP_FLAGS_SYN) == 0 && (syn&TCP_FLAGS_ACK) != 0){
		if (net_tcp_ip_reply_ack(request, len)){
			threeway_handshake = true; 
			tcp_step = TCP_SYN_SYN_2;
		}
		else{
			threeway_handshake = false;
		}
		return;
	}
	/* End */
	if (threeway_handshake == true){
		if ((syn&TCP_FLAGS_FIN) != 0 && (syn&TCP_FLAGS_ACK) == 0){
			net_tcp_ip_reply_fin_ack(request, len);
			tcp_step = TCP_SYN_END_1;
			return;
		}
	}
}
=======
		return;
	}
	/* Check SYN : step 3*/	
	if ((syn&TCP_FLAGS_SYN) == 0 && (syn&TCP_FLAGS_ACK) != 0){
		if (net_tcp_ip_reply_ack(request, len)){
			threeway_handshake = true; 
		}
		else{
			threeway_handshake = false;
		}
		return;
	}

	/* End */
	if (threeway_handshake == true){
		if ((syn&TCP_FLAGS_FIN) != 0 && (syn&TCP_FLAGS_ACK) == 0){{
			net_tcp_ip_reply_fin_ack(request, len);
			return;
		}
	}
}


>>>>>>> 7e059aa7f3496fc8bdc11f9b489b41d7c29ea1df
