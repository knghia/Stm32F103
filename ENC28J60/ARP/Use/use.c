
#include "use.h"
#include "arp.h"

uint8_t mac_source[6] = {0x08,0x10,0x19,0x97,0x25,0x25};
uint8_t ip_source[4] = {192,168,137,100};

uint8_t mac_target[6] = {0x00,0x00,0x00,0x00,0x00,0x0};
uint8_t ip_target[6] = {192,168,137,10};

extern void setup(void){
	arp_init(mac_source, ip_source);
	arp_get_mac(mac_target, ip_target);
}

extern void loop(void){
	HAL_Delay(1000);
}
