
#include "use.h"


#define GPIOA_ENABLE_CLOCK() {RCC->APB2ENR |= (1<<2);}
#define GPIOC_ENABLE_CLOCK() {RCC->APB2ENR |= (1<<4);}
#define UART_2_ENABLE_CLOCK() {RCC->APB1ENR |= (1<<17);}

void uart_2_init(void){
	
	GPIOA_ENABLE_CLOCK();									// gpioa enable clock
	GPIOA->CRL &=~ 0x0000FF00;
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
	USART2->CR1 |= (1<<5)|(1<<7);
	/* Enable interrupt */
	NVIC->IP[9] = (0<<16);
	NVIC->ISER[1] = (1<<6);
}
#define LEN_BUFF 255

uint8_t _tx_buffer[LEN_BUFF];
volatile uint16_t _head = 0;
volatile uint16_t _tail = 0;

void USART2_IRQHandler(void) {
	uint8_t c;
	if( (USART2->SR & (1<<7)) && (USART2->CR1 & (1<<7))){
		if(_head == _tail){
			USART2->CR1 &=~ (1<<7);
		}
		else{
			c = _tx_buffer[_tail];
			_tail = (_tail + 1) % LEN_BUFF;
			USART2->DR = c;
		}
	}
	USART2->SR &=~ (1<<7);
}

void uart_write(uint8_t c){
	uint16_t i = _head + 1;
	while(i == _tail);
	_tx_buffer[_head] = c;
	_head = (_head+1)%LEN_BUFF;
	USART2->CR1 |= (1<<7);
}

void uart_print(uint8_t* s){
	while(*s != 0){
		uart_write(*s);
		s++;
	}
}


extern void setup(void){
	uart_2_init();
	
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= (B0110<<20);
}

#define LED_OFF() 		{GPIOC->ODR |= (1<<13);}
#define LED_ON() 			{GPIOC->ODR &=~ (1<<13);}
#define LED_TOGGLE()	{GPIOC->ODR ^= (1<<13);}

extern void loop(void){
	
	uart_print("khac nghia\r\n");
	LED_OFF();
	HAL_Delay(500);
	LED_ON();
	HAL_Delay(500);
}
