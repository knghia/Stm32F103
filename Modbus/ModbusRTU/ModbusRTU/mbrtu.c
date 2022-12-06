#include "main.h"
#include "mbrtu.h"
#include "crc16.h"

void mbrtu_tim_init(void){
	/* 0. Enable cleck tim 2 */
	RCC->APB1ENR |= (1<<0);
	TIM2->CNT = 0;
	TIM2->PSC = 360-1;
	TIM2->ARR = 50000-1;
	/* 1. Enable UDIS tim 2 */
	TIM2->CR1 &=~	(1<<1);
	/* 2. Update interrupt enable */
	TIM2->SR = 0;
	/* 3. Update interrupt enable */
	TIM2->DIER |= (1<<0);
	/* 
		NVIC TIM 2 update : 28
		28/4 = 7
		(28-4*7)= 0-> (0)*8 = 0
	*/
	NVIC->IP[7] = (0<<0);
	/* 
		NVIC TIM 2 update : enable
		28/31 = 0
		28-31*0= 28
	*/
	NVIC->ISER[0] = (1<<28);
	/* 4. Enable time 1 */
	TIM2->CR1 |= (1<<0);
}

void mbrtu_tim_start(void){
	TIM3->SR = 0;
	TIM3->CR1 |= (1<<0);
}

void mbrtu_tim_stop(void){
	TIM3->SR = 0;
	TIM3->CR1 &=~ (1<<0);
}

void mbrtu_usart_init(void){
	/* GPIOD enable clock */
	RCC->AHB1ENR |= (1<<3);
	/* PD5 - PD6 : alternate function mode */
	GPIOD->MODER |= (2<<10)|(2<<12);
	/* select number of line alternate function */
	GPIOD->AFR[0] |= (7<<20)|(7<<24);
	GPIOD->OSPEEDR |= (2<<10)|(2<<12);

	/* UART 2 enable clock */
	RCC->APB1ENR |= (1<<17);
	/* 8 bit */
	USART2->CR1 &=~ (1<<12);
	/* parity none */
	USART2->CR1 &=~ (1<<9);
	/* SR = 0 */
	USART2->SR = 0;
	/* RE=1.. Enable the Receiver */
	USART2->CR1 |= (1<<2);
	/* TE=1.. Enable Transmitter */
	USART2->CR1 |= (1<<3);
	/*
	 * 	Fclk = 42Mhz
	 *	Baudrate : 115200
	 */
	USART2->BRR = 0x016D;
	/* UE = 1... Enable USART */
	USART2->CR1 |= (1<<13);
	/* 
		NVIC uart 2 set priority
		38%4 = 9
		(38-4*9)= 2 -> 2*4 = 8
	*/
	NVIC->IP[9] = (0<<8);
	/* 
	NVIC enable uart 2 interruput : 38
		38/32 = 1
		38-32*1 = 6
	*/
	NVIC->ISER[1] = (1<<6);
	/* Enable RS485 TE */
	RCC->AHB1ENR |= (1<<3);
	GPIOD->MODER |= (1<<14);
	GPIOD->OSPEEDR |= (2<<14);
}

#define RS485_RECEIVE()					(GPIOD->ODR &=~(1<<7))
#define RS485_TRANSMIT()				(GPIOD->ODR |= (1<<7))

void mbrtu_tx_enable(void){
	RS485_TRANSMIT();
	/* Clean SR Tx */
	USART2->SR &=~ (1<<6);
	/* UART 2 transmit enable */
	USART2->CR1 &=~ (1<<5);
	USART2->CR1 |= (1<<6);
}

void mbrtu_rx_enable(void){
	RS485_RECEIVE();
	/* Clean SR Rx */
	USART2->SR &=~ (1<<5);
	/* UART 2 receive enable */
	USART2->CR1 &=~ (1<<6);
	USART2->CR1 |= (1<<5);
}

uint8_t mbrtu_rx_read(void){
	return USART2->DR;
}

#define MAX_RX_LEN 32
#define MAX_TX_LEN 32
volatile uint8_t tx_header = 0;
volatile uint8_t tx_data[MAX_TX_LEN];

volatile uint8_t rx_data[MAX_RX_LEN] = {0};
volatile uint8_t rx_header = 0;
volatile MBRTU_State mbrtu_status = RX_IDLE;
volatile uint8_t time_detect = 0;

extern void mbrtu_init(void){
#ifndef MBRTU_ID
	 #error "Don't define MRRTU_ID"
#endif
	mbrtu_status = RX_IDLE;
	mbrtu_usart_init();
	mbrtu_tim_init();
}

extern MBRTU_Error mbrtu_poll(void){
	switch (mbrtu_status){
		case RX_IDLE:{
			rx_header = 0;
			mbrtu_status = RX_START;
			mbrtu_tim_start();
			mbrtu_rx_enable();
			break;
		}
		case RX_COMPLETE:{
			tx_header = 0;
			mbrtu_status = TX_IDLE;
			
			mbrtu_tim_stop();
			mbrtu_tx_enable();
			mbrtu_execute((uint8_t*)rx_data, rx_header);
			break;
		}
		case TX_COMPLETE:{
			mbrtu_status = RX_IDLE;
			break;
		}
		default:
			break;
	}
	return (MBRTU_Error)mbrtu_status;
}

extern void mbrtu_rx_call_back(void){
	static uint8_t c;
	if (mbrtu_status==RX_START){
		c = mbrtu_rx_read();
		rx_data[rx_header++] = c;
		rx_header = rx_header%MAX_RX_LEN;
		time_detect = 35;
	}
	else{
		rx_header = 0;
	}

}

extern void mbrtu_tim_call_back(void){
	if (time_detect > 0){
		time_detect-=1;
		if (time_detect == 0){
			mbrtu_status = RX_COMPLETE;
		}
	}
}

void mbrtu_execute(uint8_t* line, uint16_t len){
	uint8_t id = 0x00;
	uint8_t func = 0x00;
	uint16_t start_add = 0x00;
	uint16_t len_register = 0x00;
	MBRTU_Error error = MB_NONE;
	uint8_t dest_frame[MAX_RX_LEN];
	if (mbrtu_status == TX_IDLE){
		uint16_t crc = line[len-1]<<8;
		crc += line[len-2];

		if (crc16(line,len-2) == crc){
			id = *line++;

			if(id == MBRTU_ID){
				func = *line++;

				switch (func){
					case MBRTU_FUNC_04:{
						start_add = *line++<<8;
						start_add += *line++;
						len_register = *line++<<8;
						len_register += *line++;
						error = mbrtu_input_register_cb(dest_frame, start_add, len_register);

						if (error != MB_NONE){
							mbrtu_response_error(error);
						}
						else{
							mbrtu_response(func, start_add, len_register, dest_frame);
						}

						break;
					}
					case MBRTU_FUNC_06:{
						start_add = *line++<<8;
						start_add += *line++;

						dest_frame[0] = *line++;
						dest_frame[1] = *line++;

						error = mbrtu_holding_register_cb(dest_frame, start_add, 1);
						if (error != MB_NONE){
							mbrtu_response_error(error);
						}
						else{
							mbrtu_response(func, start_add, 1, dest_frame);
						}
						break;
					}
					case MBRTU_FUNC_16:{

						start_add = *line++<<8;
						start_add += *line++;

						len_register = *line++<<8;
						len_register += *line++;
						len_register = *line++;

						for(uint8_t i=0;i<len_register;i++){
							dest_frame[i] = *line++;
						}

						error = mbrtu_holding_register_cb(dest_frame, start_add, (uint16_t)len_register/2);
						if (error != MB_NONE){
							mbrtu_response_error(error);
						}
						else{
							mbrtu_response(func, start_add, (uint16_t)len_register/2, dest_frame);
						}
						break;
					}
					default:{
						mbrtu_response_error(MB_FUNC_ERROR);
						break;
					}
				}
			}
			else{
				mbrtu_response_error(MB_ID_ERROR);
			}
		}
		else{
			mbrtu_response_error(MB_CRC_ERROR);
		}
	}
}

void mbrtu_response_error(MBRTU_Error e){
	uint8_t len = 0;
	switch (e){
		case MB_ID_ERROR:{
			len = 10;
			for(uint8_t i=0;i<len;i++){
				tx_data[i] =(uint8_t) MBRTU_MES_ID_ERROR[i];
			}
			break;
		}
		case MB_FUNC_ERROR:{
			len = 19;
			for(uint8_t i=0;i<len;i++){
				tx_data[i] =(uint8_t) MBRTU_MES_FUNC_ERROR[i];
			}
			break;
		}
		case MB_ADD_ERROR:{
			len = 19;
			for(uint8_t i=0;i<len;i++){
				tx_data[i] =(uint8_t) MBRTU_MES_ADD_ERROR[i];
			}
			break;
		}
		case MB_CRC_ERROR:{
			len = 15;
			for(uint8_t i=0;i<len;i++){
				tx_data[i] =(uint8_t) MBRTU_MES_CRC_ERROR[i];
			}
			break;
		}
		default:
			break;
	}
	mbrtu_tx_data(len);
}

void mbrtu_response(uint8_t func, uint16_t add, uint16_t len, uint8_t* data){
	switch (func){
		case MBRTU_FUNC_04:{
			uint16_t i, crc;
			uint8_t len_2 = 2*(uint8_t)len;
			tx_data[0] = MBRTU_ID;
			tx_data[1] = func;
			tx_data[2] = len_2;
			for(i = 0; i < len_2; i++) {
				tx_data[3+i] = *data++;
			}
			crc = crc16((uint8_t*)tx_data, 3+len_2);
			tx_data[len_2+3] = crc%256;
			tx_data[len_2+4] = crc>>8;
			mbrtu_tx_data(len_2+5);
			break;
		}
		case MBRTU_FUNC_06:{
			uint16_t crc;
			tx_data[0] = MBRTU_ID;
			tx_data[1] = func;
			tx_data[2] = add>>8;
			tx_data[3] = add%256;

			tx_data[4] = *data++;
			tx_data[5] = *data++;

			crc = crc16((uint8_t*)tx_data, 6);
			tx_data[6] = crc%256;
			tx_data[7] = crc>>8;
			mbrtu_tx_data(8);
			break;
		}
		case MBRTU_FUNC_16:{
			uint16_t crc = 0;
			tx_data[0] = MBRTU_ID;
			tx_data[1] = func;
			tx_data[2] = add>>8;
			tx_data[3] = add%256;
			tx_data[4] = len>>8;
			tx_data[5] = len%256;
			crc = crc16((uint8_t*)tx_data, 6);
			tx_data[6] = crc%256;
			tx_data[7] = crc>>8;
			mbrtu_tx_data(8);
			break;
		}
		default:
			break;
	}
}

extern void mbrtu_tx_call_back(void){
	static uint8_t k = 1;
	if (mbrtu_status == TX_START){
		if(tx_header-- > 0){
			USART2->DR = tx_data[k++];
		}
		if(tx_header == 0){
			mbrtu_status = TX_COMPLETE;
			k = 1;
			tx_header = 0;
		}
	}
}

void mbrtu_tx_data(uint8_t len){
	if (mbrtu_status == TX_IDLE){
		mbrtu_status = TX_START;
		tx_header = len;
		USART2->DR = tx_data[0];
	}
}
