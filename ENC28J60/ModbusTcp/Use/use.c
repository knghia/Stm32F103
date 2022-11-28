#include <stdio.h>
#include "use.h"

#define REG_INPUT_NREGS 5
#define REG_INPUT_START 1000
u16 usRegInputBuf[REG_INPUT_NREGS] = {0};

#define REG_HOLDING_NREGS 4
#define REG_HOLDING_START 2000
u16 usRegHoldingBuf[REG_HOLDING_NREGS] = {7,100,255,255};


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
u16 myport = 80;

extern void setup(void){
	setup_io();
	net_init(mymac, myip, myport);
}

extern void loop(void){
	net_poll();
	delay_ms(100);
	usRegInputBuf[0] = usRegHoldingBuf[0];
	usRegInputBuf[1] = usRegHoldingBuf[1];
	usRegInputBuf[2] = usRegHoldingBuf[1];
	usRegInputBuf[3] = usRegHoldingBuf[3];
}

extern MBTCP_Error net_mb_tcp_input_register_cb(u08* data_frame, u16 begin_add, u16 len){
	if((begin_add >= REG_INPUT_START)
        && ((begin_add + len)<=(REG_INPUT_NREGS+REG_INPUT_START))){

		u16 i = begin_add-REG_INPUT_START;
        while(len>0){
            *data_frame++ = (u08)(usRegInputBuf[i]>>8);
            *data_frame++ = (u08)(usRegInputBuf[i]%256);
            i++;
            len--;
        }
		return MBTCP_NONE;
	}
	return MBTCP_ADD_ERROR;
}

extern MBTCP_Error net_mb_tcp_holding_register_cb(u08* data_frame, u16 begin_add, u16 len){
	if((begin_add >= REG_HOLDING_START)
        && ((begin_add + len)<=(REG_HOLDING_START + REG_HOLDING_NREGS)))
	{
		u16 i = begin_add-REG_HOLDING_START;
        while(len>0){
            usRegHoldingBuf[i] = (u16)(*data_frame++ << 8);
            usRegHoldingBuf[i] += (u16)(*data_frame++);
            i++;
            len--;
        }
		return MBTCP_NONE;
	}
	return MBTCP_ADD_ERROR;
}
