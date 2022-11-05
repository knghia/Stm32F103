
/*
#include <stdio.h>
#include "use.h"
#include "arp.h"
#include "support.h"
#include "crc.h"

uint8_t mac_source[6] = {0x08,0x10,0x19,0x97,0x25,0x25};
uint8_t ip_source[4] = {192,168,137,100};

uint8_t mac_target[6] = {0x00,0x00,0x00,0x00,0x00,0x0};
uint8_t ip_target[6] = {192,168,137,10};

uint8_t data[100] = {0};
uint8_t len = 0;

extern void setup(void){
	arp_init(mac_source, ip_source);
	arp_get_mac(mac_target, ip_target, 1000);
}

extern void loop(void){
}
*/

#include <stdio.h>
#include "use.h"
#include "arp.h"
#include "support.h"
#include "crc.h"

uint8_t data[100] = {0};
uint8_t len = 0;
uint8_t mac_source[6] = {0x08,0x10,0x19,0x97,0x25,0x25};
uint8_t ip_source[4] = {192,168,137,100};

uint8_t mac_target[6] = {0};
uint8_t ip_target[6] = {0};

extern void setup(void){
	arp_init(mac_source, ip_source);
	while(1){
		if (arp_receiver_package(data, &len)){
			uint32_t crc = crc32(data, len-4);
			uint32_t check_crc = (data[len-1]<<24)+(data[len-2]<<16)+(data[len-3]<<8)+data[len-4];
			if (check_crc == crc){
				if((data[ARP_I_OPCODE] == 0x00) && (data[ARP_I_OPCODE+1] == 0x01)){
					copy_array(mac_target, &data[ARP_I_MAC_SENDER], 6);
					copy_array(ip_target, &data[ARP_I_IP_SENDER], 4);
					#ifdef DEBUG_ARP
					for(uint8_t i=0;i<6;i++){
						printf("%02x ", mac_target[i]);
					}
					printf("\r\n");
					for(uint8_t i=0;i<4;i++){
						printf("%02x ", ip_target[i]);
					}
					#endif
					arp_send_responce(mac_target, ip_target);
					break;
				}
			}
		}
	}
}

extern void loop(void){

}

