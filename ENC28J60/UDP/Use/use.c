
#include <string.h>
#include "use.h"
#include "arp.h"
#include "udp.h"

const uint16_t port_dest = 5002;
const uint8_t ip_dest[4]={192, 168, 137, 10};
uint8_t mac_dest[6]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

extern void setup(void){
	/* Enable clock GPIOC */
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
	
	arp_get_mac(mac_dest, ip_dest);
}

#define LED_ON() 			{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() 		{GPIOC->ODR |= (1<<13);}
#define LED_TOGGLE() 	{GPIOC->ODR ^= (1<<13);}

extern void loop(void){
	udp_send_package(mac_dest, ip_dest, 5002, "LED1", 4);
//	udp_receive_package();
	HAL_Delay(1000);
}
