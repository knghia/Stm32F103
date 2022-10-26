
#include <string.h>
#include "use.h"
#include "arp.h"
#include "udp.h"
#include "icmp.h"

const uint8_t ip_dest[4]={192, 168, 137, 10};
uint8_t mac_dest[6]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

extern void setup(void){
	/* Enable clock GPIOC */
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
	
	arp_get_mac(mac_dest, ip_dest);
	icmp_send_package(mac_dest, ip_dest, "abcd", 4);
}

#define LED_ON() 			{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() 		{GPIOC->ODR |= (1<<13);}
#define LED_TOGGLE() 	{GPIOC->ODR ^= (1<<13);}

extern void loop(void){
	icmp_receive_package();
	HAL_Delay(2000);
}
