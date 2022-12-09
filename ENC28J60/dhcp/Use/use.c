#include <stdio.h>
#include "use.h"

extern void setup_io(void){
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

#define LED_OFF() 		{GPIOC->ODR |= (1<<13);}
#define LED_ON() 			{GPIOC->ODR &=~ (1<<13);}
#define LED_TOGGLE() 	{GPIOC->ODR ^= (1<<13);}

void enc28j60IntCallBack(void){
	printf("interrupt \r\n");
}

u08 _mymac[6] = {0x08,0x10,0x19,0x97,0x25,0x25};
u08 _myip[4] =  {192,168,137,100};       
u16 _myport = 80;
u08 _ip_of_pc[4] =  {192,168,137,10};    

extern void setup(void){
	setup_io();
	net_init(_mymac, _myip, _myport, _ip_of_pc);
}

extern void loop(void){
	net_poll();
	net_dhcp_discover();
	delay_ms(2000);
}
