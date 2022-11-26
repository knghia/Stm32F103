#include "use.h"

#define LED_OFF() 		{GPIOC->ODR |= (1<<13);}
#define LED_ON() 			{GPIOC->ODR &=~ (1<<13);}
#define LED_TOGGLE()	{GPIOC->ODR ^= (1<<13);}

u08 copy_arr(u08* dest, u08* source, u16 len){
	for(u08 i=0;i<len;i++){
		dest[i] = source[i];
	}
	return len;
}

bool com_arr(u08* a, u08* b, u16 len){
	for(u08 i=0;i<len;i++){
		if(a[i] != b[i]){
			return false;
		}
	}
	return true;
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
	USART1->CR1 |= (1<<5);
	USART1->CR1 &=~ (1<<7);
	/* Enable interrupt 37*/
	NVIC_SetPriority(USART1_IRQn, 0);
	NVIC_EnableIRQ(USART1_IRQn);
}

typedef enum{
	TX_IDLE = 0,
	TX_START = 1,
	RX_IDLE = 2
}UART_Status;

#define LEN_BUFF 255
u08 tx_buffer[LEN_BUFF];
volatile u16 tx_head = 0;
volatile u16 tx_tail = 0;

u08 rx_buffer[LEN_BUFF];
volatile u16 rx_head = 0;
volatile u16 rx_tail = 0;

volatile UART_Status uart_status = RX_IDLE;

void USART1_IRQHandler(void) {
	u08 c;
	if( (USART1->SR & (1<<7)) && (USART1->CR1 & (1<<7))){
		if (uart_status == TX_START){
			c = tx_buffer[tx_head];
			USART1->DR = c;
			tx_head = (tx_head+1)%LEN_BUFF;
			
			if(tx_head == tx_tail){
				uart_status = RX_IDLE;
				USART1->CR1 &=~ (1<<7);
			}
		}
		USART1->SR &=~ (1<<7);
		return;
	}
	
	if( (USART1->SR & (1<<5)) && (USART1->CR1 & (1<<5))){
		if(uart_status == RX_IDLE){
			c = USART1->DR;
			rx_buffer[rx_head] = c;
			rx_head = (rx_head+1)%LEN_BUFF;
		}
		USART1->SR &=~ (1<<5);
		return;
	}
}

u08 nextion_tail[3] = {0xFF, 0xFF, 0xFF};

void nextion_send(u08* id_data, u16 id_len, u08* data, u16 len){
	if(uart_status == TX_IDLE){
		
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
		uart_status = TX_START;
		USART1->DR = tx_buffer[0];
		USART1->CR1 |= (1<<7);
	}
}

bool uart2_read(u08* c){
	if(uart_status == RX_IDLE){
		if (rx_tail == rx_head){
			return false;
		}
		*c = rx_buffer[rx_tail];
		rx_tail = (rx_tail+1)%LEN_BUFF;
		return true;
	}
	return false;
}

const u08 bt_clicked[4] = {0x65, 0x00, 0x02, 0x01};

void nextion_handle(u08* data, u16 len){
	static u08 len_status = 0;
	if (len == 4){
		if (com_arr(data, (u08*)bt_clicked, len)){
			if (len_status == 0){
				len_status = 1;
				LED_ON();
				uart_status = TX_IDLE;
				nextion_send((u08*)"t0",2,(u08*)"\"ON\"",4);
			}
			else{
				len_status = 0;
				LED_OFF();
				uart_status = TX_IDLE;
				nextion_send((u08*)"t0",2,(u08*)"\"OFF\"",5);
			}
		}
	}
	for(u08 i=0;i<len;i++){
		printf("%02x ",data[i]);
	}
	printf("\r\n");
}

void nextion_poll(void){
	static u08 line[LEN_BUFF];
	static u08 index = 0;
	static u08 check = 0;
	
	if(uart_status == RX_IDLE){
		u08 c = 0;
		if(uart2_read(&c)){
			if (c == 0xFF){
				check +=1;
			}
			else{
				line[index] = c;
				index = (index+1)%LEN_BUFF;
			}
			if (check == 3){
				nextion_handle(line, index);
				index = 0;
				check = 0;
			}
		}
	}
}

extern void setup(void){
	uart1_init();
	
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= (B0110<<20);
}

extern void loop(void){
	nextion_poll();
}



