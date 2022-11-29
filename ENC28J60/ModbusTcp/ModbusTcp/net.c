#include "main.h"

u16 source_port = 80;
u08 mac_addr[6] = {0};
u08 ip_addr[4] = {0};

u08 mac_pc[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
u08 ip_pc[4] = {192,168,137,10};

extern void net_init(u08 mymac[6], u08 myip[4], u16 myport){
/* 
	u08 debug = 0xFF;
	enc28j60Init(mymac);  
	debug = enc28j60getrev();
 */
	/* INIT ENC28J60 */
	enc28j60Init(mymac);  
	enc28j60getrev();
	enc28j60PhyWrite(PHLCON, 0x476);
	/* change clkout from 6.25MHz to 12.5MHz */
	enc28j60clkout(2);
	/* INIT NET */
	source_port = myport;
	copy_arr(mac_addr, mymac, 6);
	copy_arr(ip_addr, myip, 4);
	net_arp_get_mac_ip_pc(mac_pc, ip_pc, 1000);
}

extern bool net_poll(void){
	static u08 rx_buf[BUFFER_SIZE+1] = {0};
	static u16 plen = 0;

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
		else if(rx_buf[I_IPV4_PROTOCOL] == IPV4_PROTOCOL_TCP){
			protocol = TCP_IP;
		}
		
		switch (protocol){
			case ARP:{
				if (net_arp_check_broadcast((u08*)rx_buf, plen) == true){
					net_arp_reply((u08*)rx_buf, plen);
					return true;
				}
				net_arp_reply((u08*)rx_buf, plen);
				break;
			}
			case ICMP:{
				if (net_icmp_check((u08*)rx_buf, plen) == true){
					net_icmp_reply((u08*)rx_buf, plen);
					return true;
				}
				break;
			}
			case TCP_IP:{
				if (net_mb_tcp_check((u08*)rx_buf, plen) == true){
					net_mb_tcp_reply((u08*)rx_buf, plen);
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
	if(ping[I_IPV4_ETHERNET_TYPE_H] == IPV4_ETHERNET_TYPE_H && \
	 ping[I_IPV4_ETHERNET_TYPE_L] != IPV4_ETHERNET_TYPE_L){
		return false;
	}
	/* check  protocol IPv4 - 0x0806*/
	if(((ping[I_ARP_ETHERNET_TYPE_H]<<8) + ping[I_ARP_ETHERNET_TYPE_L]) != ARP_ETHERNET_TYPE){
		return false;
	}
	return true;
}

extern void net_arp_reply(u08* ping, u16 len){
	ARP_Frame arp_data;
	copy_arr((u08*)&arp_data, ping, len);
	
	copy_arr(arp_data.MAC_dest, &ping[6], 6);
	copy_arr(arp_data.MAC_source, &ping[0], 6);
	arp_data.Opcode = swap16(ARP_OPCODE_REPLY);
	copy_arr(arp_data.MAC_sender, mac_addr, 6);
	copy_arr(arp_data.IP_sender, ip_addr, 4);
	copy_arr(arp_data.MAC_target, &ping[I_ARP_MAC_SENDER], 6);
	copy_arr(arp_data.IP_target, &ping[I_ARP_MAC_TARGET], 4);
	net_send_frame(ARP_PACKET_LEN, (u08*)&arp_data);
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
		net_send_frame(ARP_PACKET_LEN, (u08 *)&arp_struct);
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
	/* TCP protocol : 0x0800 */
	if(ping[I_IPV4_ETHERNET_TYPE_H] == IPV4_ETHERNET_TYPE_H && \
	 ping[I_IPV4_ETHERNET_TYPE_L] != IPV4_ETHERNET_TYPE_L){
		return false;
	}
	/* ICMP protocol : 0x01 */
	if (ping[I_IPV4_PROTOCOL] != IPV4_PROTOCOL_ICMP){
		return false;
	}
	return true;
}

extern void net_icmp_reply(u08* ping, u16 len){
	ICMP_Frame icmp_struct;
	copy_arr((u08*)&icmp_struct, ping, len);
	
	copy_arr(icmp_struct.MAC_dest, &ping[6], 6);
	copy_arr(icmp_struct.MAC_source,  &ping[0], 6);
	icmp_struct.CheckSum = 0x0000;
	icmp_struct.CheckSum = ipv4_checksum((u08 *)&icmp_struct.Header_length, IPV4_SIZE);
	copy_arr(icmp_struct.SourceIP, &ping[I_IPV4_DEST_IP], 4);
	copy_arr(icmp_struct.DestIP, &ping[I_IPV4_SOURCE_IP], 4);
	icmp_struct.ICMP_Type = ICMP_REPLY;
	icmp_struct.ICMP_Checksum = 0x0000;
	copy_arr(icmp_struct.ICMP_Data, &ping[IPV4_ICMP_SIZE], len-IPV4_ICMP_SIZE);
	icmp_struct.ICMP_Checksum = icmp_checksum((u08*)&(icmp_struct.ICMP_Type), ICMP_SIZE+ len-IPV4_ICMP_SIZE);
	net_send_frame(len, (u08*)&icmp_struct);
}

extern bool net_mb_tcp_check(u08* request, u16 len){
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
	/* check  protocol IPv4 - 0x0800*/
	if(request[I_IPV4_ETHERNET_TYPE_H] == IPV4_ETHERNET_TYPE_H && \
	 request[I_IPV4_ETHERNET_TYPE_L] != IPV4_ETHERNET_TYPE_L){
		return false;
	}
	/* TCP protocol : 0x06 */
	if (request[I_IPV4_PROTOCOL] != IPV4_PROTOCOL_TCP){
		return false;
	}
	return true;
}

u32 seq_num_local, ack_num_local = 0;

extern void net_mb_tcp_reply(u08* request, u16 len){
	u32 total_len = 0;
	u32 seq_num, ack_num = 0;
	u08 flags = request[I_TCP_FLAGS_L];
	MBTCP_Frame mbtcp_struct;
	copy_arr((u08*)&mbtcp_struct, request, len);

	switch (flags){
		case TCP_FLAGS_SYN:{
			/* Check SYN */
			copy_arr(mbtcp_struct.MAC_dest, &request[6], 6);
			copy_arr(mbtcp_struct.MAC_source, &request[0], 6);
			mbtcp_struct.CheckSum = 0x0000;
			mbtcp_struct.CheckSum = ipv4_checksum((u08 *)&mbtcp_struct.Header_length, IPV4_SIZE);
			copy_arr(mbtcp_struct.SourceIP, &request[I_IPV4_DEST_IP], 4);
			copy_arr(mbtcp_struct.DestIP, &request[I_IPV4_SOURCE_IP], 4);
			mbtcp_struct.TCP_Source_Port = swap16((request[I_TCP_DST_PORT_H]<<8) + request[I_TCP_DST_PORT_L]);
			mbtcp_struct.TCP_Dest_Port = swap16((request[I_TCP_SRC_PORT_H]<<8) + request[I_TCP_SRC_PORT_L]);
			
			seq_num =  swap32((request[I_TCP_SEQ_NUM]<<24) + (request[I_TCP_SEQ_NUM+1]<<16) + \
			(request[I_TCP_SEQ_NUM+2]<<8) + request[I_TCP_SEQ_NUM+3] + 1);
			ack_num = swap32(0x08101997);

			copy_arr(mbtcp_struct.TCP_Seq_Number, (u08*)&ack_num, 4);
			copy_arr(mbtcp_struct.TCP_Ack_Number, (u08*)&seq_num, 4);
			
			mbtcp_struct.TCP_Flags = TCP_FLAGS_SYN|TCP_FLAGS_ACK;
			mbtcp_struct.TCP_Window = swap16((request[I_TCP_WIN_H]<<8) + request[I_TCP_WIN_L]);
			
			total_len = (request[I_IPV4_TOTAL_LENGTH_H]<<8) + request[I_IPV4_TOTAL_LENGTH_L];
			mbtcp_struct.TCP_Checksums = 0x0000;
			mbtcp_struct.TCP_Checksums = tcp_checksum((u08*)mbtcp_struct.SourceIP, total_len - 20 +8);
			net_send_frame(len, (u08*)&mbtcp_struct);
			
			
			printf("mb tcp syn \r\n");
			break;
		}
		case TCP_FLAGS_ACK:{
			/* Check ACK */
			break;
		}
		case (TCP_FLAGS_FIN|TCP_FLAGS_ACK):{
			/* Check fin */
			copy_arr(mbtcp_struct.MAC_dest, &request[6], 6);
			copy_arr(mbtcp_struct.MAC_source, &request[0], 6);
			mbtcp_struct.CheckSum = 0x0000;
			mbtcp_struct.CheckSum = ipv4_checksum((u08 *)&mbtcp_struct.Header_length, IPV4_SIZE);
			copy_arr(mbtcp_struct.SourceIP, &request[I_IPV4_DEST_IP], 4);
			copy_arr(mbtcp_struct.DestIP, &request[I_IPV4_SOURCE_IP], 4);
			mbtcp_struct.TCP_Source_Port = swap16((request[I_TCP_DST_PORT_H]<<8) + request[I_TCP_DST_PORT_L]);
			mbtcp_struct.TCP_Dest_Port = swap16((request[I_TCP_SRC_PORT_H]<<8) + request[I_TCP_SRC_PORT_L]);
			
			seq_num =  swap32((request[I_TCP_SEQ_NUM]<<24) + (request[I_TCP_SEQ_NUM+1]<<16) + \
			(request[I_TCP_SEQ_NUM+2]<<8) + request[I_TCP_SEQ_NUM+3] + 1);
			ack_num = swap32(0x08101997);

			copy_arr(mbtcp_struct.TCP_Seq_Number, (u08*)&ack_num, 4);
			copy_arr(mbtcp_struct.TCP_Ack_Number, (u08*)&seq_num, 4);
			
			mbtcp_struct.TCP_Flags = TCP_FLAGS_ACK;
			mbtcp_struct.TCP_Window = swap16((request[I_TCP_WIN_H]<<8) + request[I_TCP_WIN_L]);
			
			total_len = (request[I_IPV4_TOTAL_LENGTH_H]<<8) + request[I_IPV4_TOTAL_LENGTH_L];
			mbtcp_struct.TCP_Checksums = 0x0000;
			mbtcp_struct.TCP_Checksums = tcp_checksum((u08*)mbtcp_struct.SourceIP, total_len - 20 +8);
			net_send_frame(len, (u08*)&mbtcp_struct);
			
			mbtcp_struct.TCP_Flags = TCP_FLAGS_FIN|TCP_FLAGS_ACK;
			mbtcp_struct.TCP_Checksums = 0x0000;
			mbtcp_struct.TCP_Checksums = tcp_checksum((u08*)mbtcp_struct.SourceIP, total_len - 20 +8);
			net_send_frame(len, (u08*)&mbtcp_struct);
			
			printf("mb tcp fin \r\n");
			break;
		}
		
		case TCP_FLAGS_ACK|TCP_FLAGS_PUSH:{
			/* Check PUSH */
			net_mb_tcp_handle(request, len);
			break;
		}
		
	}
}

void net_mb_tcp_handle(u08* request, u16 len){
	MBTCP_Error error = MBTCP_NONE;
	u08 mbtcp_add = 0;
	u08 mbtcp_func = 0;
	u16 mbtcp_first_reg = 0;
	u16 mbtcp_num_reg = 0;
	uint8_t dest_frame[MAX_RX_LEN];

	mbtcp_add = request[60];
	mbtcp_func = request[61];
	mbtcp_first_reg = (request[62]<<8) + request[63];
	mbtcp_num_reg = (request[64]<<8) + request[65];
	
	printf("mb tcp push \r\n");

	printf("mbtcp_add push %02x \r\n",mbtcp_add);
	printf("mbtcp_func push %02x \r\n",mbtcp_func);
	printf("mbtcp_first_reg push %04x \r\n",mbtcp_first_reg);
	printf("mbtcp_num_reg push %04x \r\n",mbtcp_num_reg);

	if (mbtcp_add == 0x01){
		switch (mbtcp_func){
			case MBTCP_FUNC_04:{
				error = net_mb_tcp_input_register_cb(dest_frame, mbtcp_first_reg, mbtcp_num_reg);
				if (error == MBTCP_NONE){
					net_mb_tcp_response(request, len, dest_frame, (u08)(mbtcp_num_reg*2));
				}
				break;
			}
			default:
				break;
		}
	}
}

extern void net_mb_tcp_response(u08* request, u16 len, u08* data, u16 len_of_data){	
	/* ACK */
	u32 seq_num, ack_num = 0;
	MBTCP_Frame mbtcp_struct;
	copy_arr((u08*)&mbtcp_struct, request, len);
	copy_arr(mbtcp_struct.MAC_dest, &request[I_ARP_MAC_SOURCE], 6);
	copy_arr(mbtcp_struct.MAC_source, &request[I_ARP_MAC_DEST], 6);
	mbtcp_struct.TotalLength = swap16(TCP_DATA_SIZE - ETHERNET_II_SIZE);
	mbtcp_struct.CheckSum = 0x0000;
	mbtcp_struct.CheckSum = ipv4_checksum((u08 *)&mbtcp_struct.Header_length, IPV4_SIZE);
	copy_arr(mbtcp_struct.SourceIP, &request[I_IPV4_DEST_IP], 4);
	copy_arr(mbtcp_struct.DestIP, &request[I_IPV4_SOURCE_IP], 4);
	mbtcp_struct.TCP_Source_Port = swap16((request[I_TCP_DST_PORT_H]<<8) + request[I_TCP_DST_PORT_L]);
	mbtcp_struct.TCP_Dest_Port = swap16((request[I_TCP_SRC_PORT_H]<<8) + request[I_TCP_SRC_PORT_L]);
	
	seq_num = swap32((request[I_TCP_SEQ_NUM]<<24) + (request[I_TCP_SEQ_NUM+1]<<16) + \
	(request[I_TCP_SEQ_NUM+2]<<8) + request[I_TCP_SEQ_NUM+3] + len_of_data);
	ack_num = swap32((request[I_TCP_ACK_NUM]<<24) + (request[I_TCP_ACK_NUM+1]<<16) + \
	(request[I_TCP_ACK_NUM+2]<<8) + request[I_TCP_ACK_NUM+3]);
	 
	copy_arr(mbtcp_struct.TCP_Seq_Number, (u08*)&ack_num, 4);
	copy_arr(mbtcp_struct.TCP_Ack_Number, (u08*)&seq_num, 4);

  mbtcp_struct.TCP_Flags = TCP_FLAGS_ACK;
  mbtcp_struct.TCP_Checksums = 0x0000;
	mbtcp_struct.TCP_Checksums = tcp_checksum((u08*)mbtcp_struct.SourceIP, 52 - 20 +8);
	net_send_frame(TCP_DATA_SIZE , (u08*)&mbtcp_struct);
	

	/* PUSH */
	mbtcp_struct.TotalLength = swap16(TCP_DATA_SIZE + len_of_data - ETHERNET_II_SIZE);
	mbtcp_struct.CheckSum = 0x0000;
	mbtcp_struct.CheckSum = ipv4_checksum((u08 *)&mbtcp_struct.Header_length, IPV4_SIZE);
	
	seq_num = swap32((request[I_TCP_SEQ_NUM]<<24) + (request[I_TCP_SEQ_NUM+1]<<16) + \
	(request[I_TCP_SEQ_NUM+2]<<8) + request[I_TCP_SEQ_NUM+3] + len_of_data);
	ack_num = swap32((request[I_TCP_ACK_NUM]<<24) + (request[I_TCP_ACK_NUM+1]<<16) + \
	(request[I_TCP_ACK_NUM+2]<<8) + request[I_TCP_ACK_NUM+3]);
	
	copy_arr(mbtcp_struct.TCP_Seq_Number, (u08*)&ack_num, 4);
	copy_arr(mbtcp_struct.TCP_Ack_Number, (u08*)&seq_num, 4);
	
	mbtcp_struct.TCP_Flags = TCP_FLAGS_ACK|TCP_FLAGS_PUSH;
	/* Transaction identifier */
	mbtcp_struct.TCP_Data[0] = request[54];
	mbtcp_struct.TCP_Data[1] = request[55];
	/* Protocol identifier */
	mbtcp_struct.TCP_Data[2] = request[56];
	mbtcp_struct.TCP_Data[3] = request[57];
	/* The length */
	mbtcp_struct.TCP_Data[4] = (len_of_data+3)>>8;
	mbtcp_struct.TCP_Data[5] = (len_of_data+3)%256;

	mbtcp_struct.TCP_Data[6] = request[60];
	mbtcp_struct.TCP_Data[7] = request[61];

	for(u08 i=0;i<len_of_data;i++){
		mbtcp_struct.TCP_Data[8+i] = data[i];
	}

	mbtcp_struct.TCP_Checksums = 0x0000;
	mbtcp_struct.TCP_Checksums = tcp_checksum((u08*)mbtcp_struct.SourceIP, TCP_DATA_SIZE - ETHERNET_II_SIZE + len_of_data + 9 - 20 +8);

	net_send_frame(TCP_DATA_SIZE + len_of_data + 9, (u08*)&mbtcp_struct);
}

extern void net_send_frame(u16 len, u08* packet){
	enc28j60PacketSend(len, packet);
}