#include <stdio.h>
#include <string.h>
#include "crc.h"
#include "arp.h"
#include "enc28j60.h"
#include "enc28j60_config.h"

volatile uint8_t _ARP_MAC_SOURCE[6];
volatile uint8_t _ARP_IP_SOURCE[4];

void arp_send_packet(uint8_t* package, uint16_t len){
	enc28j60_load_packet(package, ARP_PACKET_LEN);
}

extern void arp_init(uint8_t* mac_source,uint8_t* ip_source){
	copy_array((uint8_t*)_ARP_MAC_SOURCE, mac_source, 6);
	copy_array((uint8_t*)_ARP_IP_SOURCE, ip_source, 6);
	enc28j60_init((uint8_t*)_ARP_MAC_SOURCE);
}

extern bool arp_get_mac(uint8_t* mac_target,uint8_t* ip_target, uint16_t timeout){
	uint16_t status;
	uint8_t mac_dest[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	uint8_t data[100];
	uint8_t len = 0;
	ARP_Struct arp_struct;
	
	copy_array(arp_struct.MAC_dest, mac_dest, 6);
	copy_array(arp_struct.MAC_source, (uint8_t*)_ARP_MAC_SOURCE, 6);
	
	arp_struct.Ethernet_type = swap16(ARP_ETHERNET_TYPE);
	arp_struct.Hardwave_type = swap16(ARP_HARDWAVE_TYPE);
	arp_struct.Protocol_type = swap16(ARP_PROTOCOL_TYPE);
	arp_struct.Size = swap16(ARP_SIZE);
	arp_struct.Opcode = swap16(ARP_OPCODE_REQUEST);
	
	copy_array(arp_struct.MAC_sender, (uint8_t*)_ARP_MAC_SOURCE, 6);
	copy_array(arp_struct.IP_sender, (uint8_t*)_ARP_IP_SOURCE, 4);
	copy_array(arp_struct.MAC_target, mac_target, 6);
	copy_array(arp_struct.IP_target, ip_target, 4);

	while(timeout--){
		arp_send_packet((uint8_t *)&arp_struct, ARP_PACKET_LEN);
		delay_ms(100);
		status = enc28j60_receiver_package(data, &len);
		if ((status == true) || (timeout == 0)){
			break;
		}
	}
	if(timeout > 0){
		/* ARP OPCODE request */
		if((data[ARP_I_OPCODE]*256 +data[ARP_I_OPCODE+1])  == ARP_OPCODE_REPLY){
			/* compare MAC source */
			if(compare_array(&data[ARP_I_MAC_TARGET], (uint8_t*)_ARP_MAC_SOURCE, 6)){
				/* compare IP source */
				if(compare_array(&data[ARP_I_IP_TARGET], (uint8_t*)_ARP_IP_SOURCE, 4)){
					copy_array(mac_target, &data[ARP_I_MAC_SENDER], 6);
					#ifdef DEBUG_ARP
						printf("MAC: %02x %02x %02x %02x %02x %02x\r\n",mac_target[0], mac_target[1], mac_target[2], mac_target[3], mac_target[4], mac_target[5]);
					#endif
				}
			}
		}
		return true;
	}
	return false;
}

extern void arp_send_responce(uint8_t* mac_target,uint8_t* ip_target){
	ARP_Struct arp_struct;
	copy_array(arp_struct.MAC_dest, mac_target, 6);
	copy_array(arp_struct.MAC_source, (uint8_t*)_ARP_MAC_SOURCE, 6);
	
	arp_struct.Ethernet_type = swap16(ARP_ETHERNET_TYPE);
	arp_struct.Hardwave_type = swap16(ARP_HARDWAVE_TYPE);
	arp_struct.Protocol_type = swap16(ARP_PROTOCOL_TYPE);
	arp_struct.Size = swap16(ARP_SIZE);
	arp_struct.Opcode = swap16(ARP_OPCODE_REPLY);
	
	copy_array(arp_struct.MAC_sender, (uint8_t*)_ARP_MAC_SOURCE, 6);
	copy_array(arp_struct.IP_sender, (uint8_t*)_ARP_IP_SOURCE, 4);
	copy_array(arp_struct.MAC_target, mac_target, 6);
	copy_array(arp_struct.IP_target, ip_target, 4);

	arp_send_packet((uint8_t *)&arp_struct, ARP_PACKET_LEN);
}


