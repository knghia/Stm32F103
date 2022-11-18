#include "main.h"

u08 www_port=80;
u08 mac_addr[6] = {0};
u08 ip_addr[4] = {0};

u08 mac_pc[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
u08 ip_pc[4] = {192,168,137,10};

extern void net_init(u08 mymac[6], u08 myip[4], u08 myport){
	u08 debug = 0xFF;
	/* 1. INIT ENC28J60 */
	enc28j60Init(mymac);  
	debug = enc28j60getrev();  
	enc28j60PhyWrite(PHLCON, 0x476);
	// change clkout from 6.25MHz to 12.5MHz   
	enc28j60clkout(2);
	
	/* 1. INIT NET */
	www_port = myport;
	copy_arr(mac_addr, mymac, 6);
	copy_arr(ip_addr, myip, 4);
	
	net_arp_get_mac_ip_pc(mac_pc, ip_pc, 1000);
}

#define BUFFER_SIZE 1500

extern bool net_analysis(void){
	static u08 buf[BUFFER_SIZE+1] = {0};
	static u16 plen = 0;
	static u08 index = 0;
	plen = enc28j60PacketReceive(BUFFER_SIZE, buf);
	if (plen == 0){ 
		return false;
	}
	else{
		if (net_arp_check_broadcast(buf, plen)){
			net_arp_reply(buf, plen);
			index+=1;
			printf("arp %02d\r\n",index);
			return true;
		}
		if (net_icmp_check(buf, plen)){
			net_icmp_reply(buf, plen);
			index+=1;
			printf("icmp %02d\r\n",index);
			return true;
		}
	}
	return false;
}

extern bool net_arp_check_broadcast(u08* ping, u08 len){
	if (len<41){
		return false;
	}
	if(!com_arr(&ping[I_ARP_MAC_SOURCE], mac_pc, 6)){
		return false;
	}
	if(!com_arr(&ping[I_ARP_IP_TARGET], ip_pc, 4)){
		return false;
	}
	/* check  protocol IPv4 - 0x0800*/
	if(!(ping[I_ARP_PROTOCOL_TYPE] == 0x08 && ping[I_ARP_PROTOCOL_TYPE+1] == 0x00)){
		return false;
	}
	/* check  protocol IPv4 - 0x0806*/
	if(ping[I_ARP_ETHERNET_TYPE] == 0x08 && ping[I_ARP_ETHERNET_TYPE+1] == 0x06){
		return true;
	}
	return false;
}

extern void net_arp_reply(u08* ping, u08 len){
	ARP_Frame arp_data;
	copy_arr(arp_data.MAC_dest, &ping[ETH_ARP_SRC_MAC_P], 6);
	copy_arr(arp_data.MAC_source, mac_addr, 6);
	
	arp_data.Ethernet_type = swap16(ARP_ETHERNET_TYPE);
	arp_data.Hardwave_type = swap16(ARP_HARDWAVE_TYPE);
	arp_data.Protocol_type = swap16(ARP_PROTOCOL_TYPE);
	arp_data.Size = swap16(ARP_SIZE);
	arp_data.Opcode = swap16(ARP_OPCODE_REPLY);
	
	copy_arr(arp_data.MAC_sender, mac_addr, 6);
	copy_arr(arp_data.IP_sender, ip_addr, 4);
	copy_arr(arp_data.MAC_target, &ping[ETH_ARP_SRC_MAC_P], 6);
	copy_arr(arp_data.IP_target, &ping[ETH_ARP_SRC_IP_P], 4);
	
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
		delay_ms(500);
		len = enc28j60PacketReceive(BUFFER_SIZE, data); 
		if (len >= 42){
			/* ARP OPCODE request */
			uint16_t arp_opcode = (data[ETH_ARP_OPCODE_H_P]<<8) + data[ETH_ARP_OPCODE_L_P];
			if(arp_opcode == ARP_OPCODE_REPLY){
				/* compare MAC source */
				if(com_arr(&data[ETH_ARP_DST_MAC_P], (uint8_t*)mac_addr, 6)){
					/* compare IP source */
					if(com_arr(&data[ETH_ARP_DST_IP_P], (uint8_t*)ip_addr, 4)){
						copy_arr(mac_target, &data[ETH_ARP_SRC_MAC_P], 6);
						#ifdef DEBUG
							printf("MAC: %02x %02x %02x %02x %02x %02x\r\n", \
						mac_target[0], mac_target[1], mac_target[2], \
						mac_target[3], mac_target[4], mac_target[5]);
						return true;
						#endif
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

extern bool net_icmp_check(u08* data, u08 len){
	if (len<41){
		return false;
	}
	/* compare mac addr */
	if (!com_arr(&data[IPV4_I_MAC_SOURCE], mac_addr, 6)){
			return false;
	}
	/* compare mac pc */
	if (!com_arr(&data[IPV4_I_MAC_DEST], mac_pc, 6)){
			return false;
	}
	/* compare ip pc */
	if (!com_arr(&data[I_IPV4_SOURCE_IP], ip_pc, 4)){
			return false;
	}
	/* compare ip addr */
	if (!com_arr(&data[I_IPV4_DEST_IP], ip_addr, 4)){
			return false;
	}
	/* compare ICMP request */
	if (!(data[I_ICMP_TYPE] == 0x08)){
			return false;
	}
	/* ICMP protocol : 0x0800 */
	if (data[ETH_TYPE_H_P] == 0x08 && data[ETH_TYPE_L_P] == 0x00){
		if (data[0x17] == 0x01){
			return true;
		}
	}
	return false;
}

extern void net_icmp_response(u08* data, u08 length){
  static uint16_t ipv4_identification = IPV4_IDENTIFICATION;
	static uint16_t icmp_identification = ICMP_IDENTIFIER;
	static uint16_t icmp_senquence_number = ICMP_SEQUENCE_NUMBER;
	ICMP_Frame icmp_struct;
	copy_arr(icmp_struct.MAC_source, mac_addr, 6);
	copy_arr(icmp_struct.MAC_dest, mac_pc, 6);
	icmp_struct.Ethernet_type = swap16(IPV4_ETHERNET_TYPE);
	
	icmp_struct.Header_length = IPV4_HEADER_LENGTH;
	icmp_struct.Services = IPV4_SERVICES;
	icmp_struct.TotalLength = swap16(IPV4_SIZE + length);
	icmp_struct.Identification = swap16(ipv4_identification);
	icmp_struct.Flag = swap16(IPV4_FLAG);
	icmp_struct.TimeToLive = IPV4_TIME_TO_LIVE;
	icmp_struct.Protocol = IPV4_PROTOCOL_ICMP;
	icmp_struct.CheckSum = icmp_ip_checksum((u08 *)&icmp_struct.Header_length, 20);

	copy_arr(icmp_struct.SourceIP, ip_pc, 4);
	copy_arr(icmp_struct.DestIP, ip_addr, 4);

	icmp_struct.ICMP_Type = ICMP_REQUEST;
	icmp_struct.ICMP_Code = ICMP_CODE;
	icmp_struct.ICMP_Identification = swap16(icmp_identification);
	icmp_struct.ICMP_SequenceNumber = swap16(icmp_senquence_number);
	copy_arr(icmp_struct.ICMP_data, data, length);
	
	icmp_struct.ICMP_Checksum = 0x0000;
	icmp_struct.ICMP_Checksum = icmp_checksum((u08*)&(icmp_struct.ICMP_Type), ICMP_SIZE + length);
	
	enc28j60PacketSend(IPV4_ICMP_SIZE + length, (u08*)&icmp_struct);
	
	ipv4_identification+=1;
	icmp_identification+=1;
	icmp_senquence_number+=1;
}

extern void net_icmp_reply(u08* ping, u08 len){
	ICMP_Frame icmp_struct;
	copy_arr(icmp_struct.MAC_source, &ping[0], 6);
	copy_arr(icmp_struct.MAC_dest, &ping[6], 6);
	icmp_struct.Ethernet_type = swap16(IPV4_ETHERNET_TYPE);
	
	icmp_struct.Header_length = IPV4_HEADER_LENGTH;
	icmp_struct.Services = IPV4_SERVICES;
	icmp_struct.TotalLength = swap16((ping[I_IPV4_TOTAL_LENGTH]<<8) + ping[I_IPV4_TOTAL_LENGTH+1]);
	icmp_struct.Identification = swap16((ping[I_IPV4_IDENTIFICATION]<<8) + ping[I_IPV4_IDENTIFICATION+1]);
	icmp_struct.Flag = swap16(IPV4_FLAG);
	icmp_struct.TimeToLive = IPV4_TIME_TO_LIVE;
	icmp_struct.Protocol = IPV4_PROTOCOL_ICMP;
	icmp_struct.CheckSum = 0x0000;
	icmp_struct.CheckSum = icmp_ip_checksum((u08 *)&icmp_struct.Header_length, 20);
	// icmp_struct.CheckSum = 0;

	copy_arr(icmp_struct.SourceIP, ip_addr, 4);
	copy_arr(icmp_struct.DestIP, ip_pc, 4);

	icmp_struct.ICMP_Type = ICMP_REPLY;
	icmp_struct.ICMP_Code = ICMP_CODE;
	icmp_struct.ICMP_Checksum = 0x0000;
	icmp_struct.ICMP_Identification = swap16((ping[I_ICMP_IDENTIFIER]<<8) + ping[I_ICMP_IDENTIFIER+1]);
	icmp_struct.ICMP_SequenceNumber = swap16((ping[I_ICMP_SEQUENCE_NUMBER]<<8) + ping[I_ICMP_SEQUENCE_NUMBER+1]);
	copy_arr(icmp_struct.ICMP_data, &ping[42], len-42);
	
	icmp_struct.ICMP_Checksum = icmp_checksum((u08*)&(icmp_struct.ICMP_Type), ICMP_SIZE+ len-42);

	enc28j60PacketSend(len, (u08*)&icmp_struct);
}


