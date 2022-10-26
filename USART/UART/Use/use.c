
#include "use.h"


#define GPIOA_ENABLE_CLOCK() {RCC->APB2ENR |= (1<<2);}
#define GPIOC_ENABLE_CLOCK() {RCC->APB2ENR |= (1<<4);}
#define UART_2_ENABLE_CLOCK() {RCC->APB1ENR |= (1<<14);}

void uart_2_init(void){
	
	GPIOA_ENABLE_CLOCK();									// gpioa enable clock
	GPIOA->CRL |= (B1010<<8)|(B1000<<12);	// pa9 - pa10 : alternate function mode

	UART_2_ENABLE_CLOCK();

	USART2->CR1 &=~ (1<<12);	// 8 bit
	USART2->CR1 &=~ (1<<9);		// parity none
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
	
	GPIOC_ENABLE_CLOCK();
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


