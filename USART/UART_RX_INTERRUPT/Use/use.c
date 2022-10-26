
#include "use.h"

#define GPIOA_ENABLE_CLOCK() {RCC->APB2ENR |= (1<<2);}
#define GPIOC_ENABLE_CLOCK() {RCC->APB2ENR |= (1<<4);}
#define UART_1_ENABLE_CLOCK() {RCC->APB2ENR |= (1<<14);}
#define UART_2_ENABLE_CLOCK() {RCC->APB1ENR |= (1<<17);}

void uart_1_init(void){
	
	GPIOA_ENABLE_CLOCK();										// gpioa enable clock
	GPIOA->CRH &=~ 0x00000FF0;
	GPIOA->CRH |= (B1010<<4)|(B0100<<8);		// pa9 - pa10 : alternate function mode

	UART_1_ENABLE_CLOCK();

	USART1->CR1 &=~ (1<<12);	// 8 bit
	USART1->CR1 &=~ (1<<9);		// parity none
	USART1->CR1 |= (1<<2); 		// RE=1.. Enable the Receiver
	USART1->CR1 |= (1<<3);  	// TE=1.. Enable Transmitter

	/*
	 * 	Fclk = 72Mhz
	 *	Baudrate : 115200
	 */
	USART1->BRR = 0x0271;
	USART1->CR1 |= (1<<13);   // UE = 1... Enable USART
}

void uart_1_write(uint8_t c){
	USART1->DR = c;
	while (!(USART1->SR & (1<<6)));
}

void uart_1_print(uint8_t *str){
	while(*str != 0){
		uart_1_write(*str);
		str++;
	}
}

void uart_2_init(void){
	
	GPIOA_ENABLE_CLOCK();									// gpioa enable clock
	GPIOA->CRL |= (B1010<<8)|(B0100<<12);	// pa2 - pa3 : alternate function mode

	UART_2_ENABLE_CLOCK();

	USART2->CR1 &=~ (1<<12);	// 8 bit
	USART2->CR1 &=~ (1<<9);		// parity none
	USART2->CR1 |= (1<<2); 		// RE=1.. Enable the Receiver
	USART2->CR1 |= (1<<3);  	// TE=1.. Enable Transmitter

	/*
	 * 	Fclk = 36Mhz
	 *	Baudrate : 115200
	 */
	USART2->BRR = 0x0139;
	USART2->CR1 |= (1<<13);   // UE = 1... Enable USART
	
	/* USART INTERRRPUT */
	USART2->CR1 |= (1<<5);
	/* Enable interrupt */
	NVIC->IP[9] = (0<<16);
	NVIC->ISER[1] = (1<<6);
}
#define LEN_BUFF 255

uint8_t _rx_buffer[LEN_BUFF];
volatile uint16_t _head = 0;

void USART2_IRQHandler(void) {
	if( (USART2->SR & (1<<5)) && (USART2->CR1 & (1<<5))){
		_rx_buffer[_head++] = USART2->DR;
		if(_head == LEN_BUFF){
			_head = 0;
		}
	}
	USART2->SR &=~ (1<<5);
}

extern void setup(void){
	uart_1_init();
	uart_2_init();
	
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= (B0110<<20);
}

#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define LED_ON() {GPIOC->ODR &=~ (1<<13);}
#define LED_TOGGLE() {GPIOC->ODR ^= (1<<13);}

extern void loop(void){
	uart_1_print("nghia\r\n");
	HAL_Delay(500);
	LED_TOGGLE();
}
