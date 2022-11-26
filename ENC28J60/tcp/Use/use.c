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

u08 mymac[6] = {0x08,0x10,0x19,0x97,0x25,0x25};
u08 myip[4] =  {192,168,137,100};       
u16 myport = 5004;

extern void setup(void){
	setup_io();
	net_init(mymac, myip, myport);
}

extern void loop(void){
	net_poll();
	delay_ms(100);
}
