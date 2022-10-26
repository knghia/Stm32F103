
#include <string.h>
#include "use.h"
#include "arp.h"
#include "udp.h"

uint8_t IP_dest[] = {192,168,137,100};
uint16_t port_dest = 5004;
uint8_t data[] = "LED1";
uint32_t timeout = 1000;

extern void setup(void){
	/* Enable clock GPIOC */
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
	UDP_send(IP_dest,port_dest,data,4,timeout);
}

extern void loop(void){
	
	HAL_Delay(1000);
}
