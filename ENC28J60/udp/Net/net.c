#include "main.h"

u16 source_port = 80;
u08 mac_addr[6] = {0};
u08 ip_addr[4] = {0};

u08 mac_pc[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
u08 ip_pc[4] = {0};

extern void net_init(u08 mymac[6], u08 myip[4], u16 myport, u08 ip_of_pc[4]){
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
	copy_arr(ip_pc, ip_of_pc, 4);
	net_arp_get_mac_ip_pc(mac_pc, ip_pc, 100);
	
	// enable interrutps
	enc28j60WriteOp(ENC28J60_BIT_FIELD_SET, EIE, EIE_INTIE|EIE_PKTIE);
}

extern bool net_check_enit(void){
	if(enc28j60Read(EIR)&EIR_PKTIF){
		enc28j60WriteOp(ENC28J60_BIT_FIELD_CLR ,EIR, EIR_PKTIF);
		return true;
	}
	return false;
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
		if(rx_buf[I_ARP_ETHERNET_TYPE_H] == 0x08 && \
			rx_buf[I_ARP_ETHERNET_TYPE_L] == 0x06){	
			protocol = ARP;
		}
		else if(rx_buf[I_IPV4_PROTOCOL] == IPV4_PROTOCOL_ICMP){
			protocol = ICMP;
		}
		else if(rx_buf[I_IPV4_PROTOCOL] == IPV4_PROTOCOL_UDP){
			protocol = UDP;
		}
		switch (protocol){
			case ARP:{
				if (net_arp_check_broadcast((u08*)rx_buf, plen)){
					net_arp_reply();
					return true;
				}
				break;
			}
			case ICMP:{
				if (net_icmp_check((u08*)rx_buf, plen)){
					net_icmp_reply((u08*)rx_buf, plen);
					return true;
				}
				break;
			}
			case UDP:{
				if (net_udp_check((u08*)rx_buf, plen)){
					net_udp_reply((u08*)rx_buf, plen);
					return true;
				}
				break;
			}
			case TCP_IP:
				break;
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
	if(!(ping[I_ARP_PROTOCOL_TYPE_H] == 0x08 && \
		ping[I_ARP_PROTOCOL_TYPE_L] == 0x00)){
		return false;
	}
	/* check  protocol IPv4 - 0x0806*/
	if(!(ping[I_ARP_ETHERNET_TYPE_H] == 0x08 && \
		ping[I_ARP_ETHERNET_TYPE_L] == 0x06)){
			return false;
	}
	return true;
}

extern void net_arp_reply(void){
	ARP_Frame arp_data;
	copy_arr(arp_data.MAC_dest, mac_pc, 6);
	copy_arr(arp_data.MAC_source, mac_addr, 6);
	arp_data.Ethernet_type = swap16(ARP_ETHERNET_TYPE);
	arp_data.Hardwave_type = swap16(ARP_HARDWAVE_TYPE);
	arp_data.Protocol_type = swap16(ARP_PROTOCOL_TYPE);
	arp_data.Size = swap16(ARP_SIZE);
	arp_data.Opcode = swap16(ARP_OPCODE_REQUEST);
	copy_arr(arp_data.MAC_sender, mac_addr, 6);
	copy_arr(arp_data.IP_sender, ip_addr, 4);
	copy_arr(arp_data.MAC_target, mac_pc, 6);
	copy_arr(arp_data.IP_target, ip_pc, 4);
	enc28j60PacketSend(ARP_PACKET_LEN, (u08*)&arp_data);
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
		delay_ms(200);
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
	enc28j60PacketSend(len, (u08*)&icmp_struct);
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
	if (((request[I_IPV4_ETHERNET_TYPE_H]<<8)+request[I_IPV4_ETHERNET_TYPE_L]) != IPV4_ETHERNET_TYPE){
		return false;
	}
	/* UDP protocol : 0x11 */
	if (request[I_IPV4_PROTOCOL] != IPV4_PROTOCOL_UDP){
		return false;
	}
	return true;
}

extern void net_udp_reply(u08* data, u16 len){
	if (com_arr(&data[I_UDP_DATA], (u08*)"LED13=HIGH\r\n", 12)){
		net_udp_handle(0);
		net_udp_request(data, len, (u08*)"LED13=HIGH\r\n", 12);
	}
	else if (com_arr(&data[I_UDP_DATA], (u08*)"LED13=LOW\r\n", 11)){
		net_udp_handle(1);
		net_udp_request(data, len, (u08*)"LED13=LOW\r\n", 11);
	}
	else{
		net_udp_handle(2);
		net_udp_request(data, len, (u08*)"INCORRECT\r\n", 11);
	}
}

extern void net_udp_request(u08* request, u08 len, u08* data, u16 len_of_data){
	UDP_Frame udp_struct;
	copy_arr((u08*)&udp_struct, request, len);
	
	copy_arr(udp_struct.MAC_dest, &request[6], 6);
	copy_arr(udp_struct.MAC_source, &request[0], 6);
	
	udp_struct.CheckSum = 0x0000;
	udp_struct.CheckSum = ipv4_checksum((u08 *)&udp_struct.Header_length, IPV4_SIZE);
	udp_struct.TotalLength = swap16(IPV4_SIZE + UDP_SIZE	+ len_of_data);
	udp_struct.CheckSum = 0x0000;
	udp_struct.CheckSum = ipv4_checksum((u08 *)&udp_struct.Header_length, IPV4_SIZE);
	copy_arr(udp_struct.SourceIP, &request[I_IPV4_DEST_IP], 4);
	copy_arr(udp_struct.DestIP, &request[I_IPV4_SOURCE_IP], 4);
	
	udp_struct.UDP_Source_Port = swap16(source_port);
	udp_struct.UDP_Dest_Port = swap16((request[I_UDP_SRC_PORT_H]<<8) + request[I_UDP_SRC_PORT_L]);
	udp_struct.UDP_Length = swap16(UDP_SIZE + len_of_data);
	copy_arr(udp_struct.UDP_Data, data, len_of_data);
	
	/* check sum */
	udp_struct.UDP_Checksum = 0x0000;
	udp_struct.UDP_Checksum = udp_checksum((u08*)udp_struct.SourceIP, UDP_SIZE + len_of_data + 8);
	enc28j60PacketSend(I_UDP_DATA + len_of_data, (u08*)&udp_struct);	
}


__weak void net_udp_handle(u08 num){}