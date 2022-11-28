
#include "use.h"

void uart_2_init(void){
	/* gpioa enable clock */
	RCC->APB2ENR |= (1<<2);
	/* pa9 - pa10 : alternate function mode */
	GPIOA->CRL |= (B1010<<8)|(B1000<<12);

	RCC->APB1ENR |= (1<<14);
	/* Parity control enable */
	USART2->CR1 |= (1<<10);
	/* Even Parity */
	USART2->CR1 &=~ (1<<9);
	/* Word Length: 1 start, 8bit, n stop */
	USART2->CR1 &=~ (1<<12);
	/* 1 stop bit */
	USART2->CR2 &=~ (B11<<12);
	
	USART2->CR1 |= (1<<2); 		// RE=1.. Enable the Receiver
	USART2->CR1 |= (1<<3);  	// TE=1.. Enable Transmitter

	/*
	 * 	Fclk = 72Mhz
	 *	Baudrate : 115200
	 */
	USART2->BRR = 0x02D9;
	USART2->CR1 |= (1<<13);   // UE = 1... Enable USART
}

void uart_2_write(uint8_t c){
	USART2->DR = c;
	while (!(USART2->SR & (1<<6)));
}

void uart_2_print(uint8_t *str){
	while(*str != 0){
		uart_2_write(*str);
		str++;
	}
}

extern void setup(void){
	uart_2_init();
	
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH |= (B0110<<20);
}

#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define LED_ON() {GPIOC->ODR &=~ (1<<13);}

extern void loop(void){
	uart_2_print((uint8_t*)"khac nghia\r\n");
	
	LED_OFF();
	HAL_Delay(250);
	LED_ON();
	HAL_Delay(250);
}


