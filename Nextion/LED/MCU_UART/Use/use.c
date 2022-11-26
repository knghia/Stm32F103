#include <inttypes.h>
#include "use.h"

#define u08 uint8_t
#define u16 uint16_t

void copy_arr(u08* dest, u08* source, u16 len){
	for(u08 i=0;i<len;i++){
		dest[i] = source[i];
	}
}

void uart1_init(void){
	/* GPIOA enable clock */
	RCC->APB2ENR |= (1<<2);	
	GPIOA->CRH &=~ 0x00000FF0;
	GPIOA->CRH |= (B1010<<4)|(B0100<<8);		// pa9 - pa10 : alternate function mode

	RCC->APB2ENR |= (1<<14);

	USART1->CR1 &=~ (1<<12);	// 8 bit
	USART1->CR1 &=~ (1<<9);		// parity none
	USART1->CR1 |= (1<<2); 		// RE=1.. Enable the Receiver
	USART1->CR1 |= (1<<3);  	// TE=1.. Enable Transmitter
	/*
	 * 	Fclk = 72Mhz
	 *	Baudrate : 9600
	 */
	USART1->BRR = 0x1D4C;
	/* UE = 1... Enable USART */
	USART1->CR1 |= (1<<13);
	/* Usart interrupt */
	USART1->CR1 &=~ (1<<7);
	/* Enable interrupt 37*/
	NVIC_SetPriority(USART1_IRQn, 0);
	NVIC_EnableIRQ(USART1_IRQn);
}

typedef enum{
	TX_IDLE = 0,
	TX_START = 1
}TX_Status;

#define LEN_BUFF 255
u08 tx_buffer[LEN_BUFF];
volatile u16 tx_head = 0;
volatile u16 tx_tail = 0;
volatile TX_Status tx_status = TX_IDLE;

void USART1_IRQHandler(void) {
	u08 c;
	if( (USART1->SR & (1<<7)) && (USART1->CR1 & (1<<7))){
		if (tx_status == TX_START){
			c = tx_buffer[tx_head];
			USART1->DR = c;
			tx_head = (tx_head+1)%LEN_BUFF;
			
			if(tx_head == tx_tail){
				tx_status = TX_IDLE;
				USART1->CR1 &=~ (1<<7);
			}
		}
	}
	USART1->SR &=~ (1<<7);
}

u08 nextion_tail[3] = {0xFF, 0xFF, 0xFF};

void nextion_send(u08* id_data, u16 id_len, u08* data, u16 len){
	if(tx_status == TX_IDLE){
		
		for(u08 i=0;i<id_len;i++){
			tx_buffer[tx_tail] = id_data[i];
			tx_tail = (tx_tail+1)%LEN_BUFF;
		}
		
		copy_arr(&tx_buffer[tx_tail], (u08*)".txt=", 5);
		tx_tail+=5;
		
		for(u08 i=0;i<len;i++){
			tx_buffer[tx_tail] = data[i];
			tx_tail = (tx_tail+1)%LEN_BUFF;
		}
		
		copy_arr(&tx_buffer[tx_tail], nextion_tail, 3);
		tx_tail+=3;
		
		tx_head = 1;
		tx_status = TX_START;
		USART1->DR = tx_buffer[0];
		USART1->CR1 |= (1<<7);
	}
}

extern void setup(void){
	uart1_init();
	
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= (B0110<<20);
}

#define LED_OFF() 		{GPIOC->ODR |= (1<<13);}
#define LED_ON() 			{GPIOC->ODR &=~ (1<<13);}
#define LED_TOGGLE()	{GPIOC->ODR ^= (1<<13);}

extern void loop(void){
	nextion_send((u08*)"t0",2,(u08*)"\"OFF\"",5);
	LED_OFF();
	HAL_Delay(1000);
	nextion_send((u08*)"t0",2,(u08*)"\"ON\"",4);
	LED_ON();
	HAL_Delay(1000);
}



