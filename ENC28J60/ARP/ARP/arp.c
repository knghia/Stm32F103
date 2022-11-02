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

extern bool arp_receiver_package(uint8_t* mac){
	static Enc28j60Frame arp_data;
	uint16_t i =0;
	/* Enable receive */
	enc28j60_write_cmd(BFS, ECON1, (1<<RXEN));
	if( enc28j60_read_control_res(BANK_1,EPKTCNT) == 0 )
	{
		return false;
	}
	/* Set the read pointer to the start of the received packet */
	enc28j60_write_control_res(BANK_0,ERDPTL,arp_data.pointer_rx/256);
	enc28j60_write_control_res(BANK_0,ERDPTH,arp_data.pointer_rx>>8);
	/* read the next packet pointer */
	arp_data.pointer_rx = enc28j60_read_cmd(RBM, 0);
	arp_data.pointer_rx |= (enc28j60_read_cmd(RBM, 0)<<8);
	/* read the packet length (see datasheet page 43) */
	arp_data.len  = enc28j60_read_cmd(RBM, 0);
	arp_data.len |= (enc28j60_read_cmd(RBM, 0)<<8);

	arp_data.status = enc28j60_read_cmd(RBM, 0);
	arp_data.status |= (enc28j60_read_cmd(RBM, 0)<<8);
	
	if ((arp_data.status & 0x80)==0){
		arp_data.len = 0;
	}
	else{
		for(i=0;i<arp_data.len;i++){
			arp_data.rx[i] = enc28j60_read_cmd(RBM, 0);
		}
		/* compare opcode */
		if((arp_data.rx[ARP_I_OPCODE]*256 +arp_data.rx[ARP_I_OPCODE+1])  == ARP_OPCODE_REQUEST){
			/* compare MAC source */
			if(compare_array(&arp_data.rx[ARP_I_MAC_TARGET], _ARP_MAC_SOURCE, 6)){
				if(compare_array(&arp_data.rx[ARP_I_IP_TARGET], _ARP_IP_SOURCE, 4)){
					memcpy(mac, &arp_data.rx[ARP_I_MAC_SENDER], 6);
					#ifdef DEBUG_ARP
						printf("MAC: %02x %02x %02x %02x %02x %02x\r\n",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
					#endif
				}
			}
		}
		enc28j60_write_cmd(BFC, ECON1, (1<<RXEN));
		return true;
	}
	enc28j60_write_cmd(BFC, ECON1, (1<<RXEN));
	return false;
}

extern void arp_init(uint8_t* mac_source,uint8_t* ip_source){
	copy_array(_ARP_MAC_SOURCE, mac_source);
	copy_array(_ARP_IP_SOURCE, ip_source);
	enc28j60_init(_ARP_MAC_SOURCE);
}

extern bool arp_get_mac(uint8_t* mac_target,uint8_t* ip_target){
	uint16_t status;
	int16_t timeout = 1000;
	uint8_t mac_dest[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	ARP_Struct arp_struct;
	
	copy_array(arp_struct.MAC_dest, mac_dest, 6);
	copy_array(arp_struct.MAC_source, _ARP_MAC_SOURCE, 6);
	
	arp_struct.Ethernet_type = swap16(ARP_ETHERNET_TYPE);
	arp_struct.Hardwave_type = swap16(ARP_HARDWAVE_TYPE);
	arp_struct.Protocol_type = swap16(ARP_PROTOCOL_TYPE);
	arp_struct.Size = swap16(ARP_SIZE);
	arp_struct.Opcode = swap16(ARP_OPCODE_REPLY);
	
	copy_array(arp_struct.MAC_sender, _ARP_MAC_SOURCE, 6);
	copy_array(arp_struct.IP_sender, _ARP_IP_SOURCE, 4);
	copy_array(arp_struct.MAC_target, mac_target, 6);
	copy_array(arp_struct.IP_target, ip_target, 4);

	while(timeout--){
		arp_send_packet((uint8_t *)&arp_struct, ARP_PACKET_LEN);
		delay_ms(100);
		status = arp_receiver_package(mac_target);
		if (status == true){
			break;
		}
	}
	if(timeout >= 0){
		return true;
	}
	return false;
}

