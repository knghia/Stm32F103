
#include "use.h"
#include <stdbool.h>

#define GPIOA_ENABLE_CLOCK() {RCC->APB2ENR |= (1<<2);}
#define GPIOC_ENABLE_CLOCK() {RCC->APB2ENR |= (1<<4);}
#define UART_2_ENABLE_CLOCK() {RCC->APB1ENR |= (1<<17);}

void uart_2_init(void){
	
	GPIOA_ENABLE_CLOCK();					// gpioa enable clock
	GPIOA->CRL |= (10<<8)|(4<<12);	// pa2 - pa3 : alternate function mode

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
	
	/* USART RX INTERRRPUT */
	USART2->CR1 |= (1<<5);
	/* Enable interrupt */
	NVIC->IP[9] = (0<<16);
	NVIC->ISER[1] = (1<<6);
}

#define LENGTH_MAX 255
uint8_t rx_data[LENGTH_MAX];
uint8_t rx_header = 0;
uint8_t rx_tail = 0;

void USART2_IRQHandler(void) {
	if( (USART2->SR & (1<<5)) && (USART2->CR1 & (1<<5))){
		uint8_t data = USART2->DR;
		rx_data[rx_header] = data;
		rx_header = (rx_header+1)%LENGTH_MAX;
	}
	USART2->SR &=~ (1<<5);
}

void uart_2_write(uint8_t c){
	USART2->DR = c;
	while (!(USART2->SR & (1<<6)));
}

void uart_2_print(char *str){
	while(*str != 0){
		uart_2_write(*str);
		str++;
	}
}

extern uint8_t uart_2_read(void){
    if (rx_tail == rx_header){
        return 0xFF;
    }
    uint8_t data = rx_data[rx_tail];
    rx_tail = (rx_tail+1)%LENGTH_MAX;
    return data;
}

uint8_t line[255];

bool compare(char* data1, char* data2, uint8_t len){
    for(uint8_t i=0;i<len;i++){
        if(*(data1++) != *(data2++)){
            return false;
        }
    }
    return true;
}

#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define LED_ON() {GPIOC->ODR &=~ (1<<13);}
#define LED_TOGGLE() {GPIOC->ODR ^= (1<<13);}

void led_handle(uint8_t *data, uint8_t len){
    if (compare((char*)data, "LED13=1;",8)){
        LED_ON();
		uart_2_print("OK\r\n");
        return;
    }
    if (compare((char*)data, "LED13=0;",8)){
        LED_OFF();
		uart_2_print("OK\r\n");
        return;
    }
	uart_2_print("Error\r\n");
}

void protocol_execute(void){
    static uint8_t line[255];
    static uint8_t index = 0;

    uint8_t c = uart_2_read();
    if (c != 0xFF){
        if ((c == '\n') || (c == '\r')){
            line[index++] = 0;
            led_handle(line,index);
            index = 0;
        }
        else{
            line[index++] = c;
        }
    }
}

extern void setup(void){
	uart_2_init();
	uart_2_print("Welcome\r\n");
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
	
	LED_ON();
	HAL_Delay(500);
	LED_OFF();
	HAL_Delay(500);
}


extern void loop(void){
	protocol_execute();
}
