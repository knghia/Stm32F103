
#include "use.h"
#include "arp.h"

uint8_t mac_target[6] = {0x00,0x00,0x00,0x00,0x00,0x0};
const uint8_t ip_target[6] = {192,168,137,10};

extern void setup(void){
	/* Enable clock GPIOC */
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
	
	arp_get_mac(mac_target, ip_target);
}

#define LED_ON() 			{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() 		{GPIOC->ODR |= (1<<13);}
#define LED_TOGGLE() 	{GPIOC->ODR ^= (1<<13);}

extern void loop(void){
	HAL_Delay(1000);
}
