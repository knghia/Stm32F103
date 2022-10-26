#include <stdio.h>
#include "use.h"
#include "binary.h"
#include "st7735.h"
#include "st7735_graphics.h"
#include "st7735_text.h"

void ssd1306_clear_graphic(void){
	int i,j;
	for(i=29;i<128;i++){
		for(j=29;j<160;j++){
			ST7735_Pixel(i,j,RGB565(0, 0, 0));
		}
	}
}

void gui_main(){
	ST7735_Init();
	ST7735_Clear(0x0000);
	
	ST7735_FillRect(4, 4, 16, 115, 0x1FE5); 
	ST7735_FillRect(4+3*8, 4, 4+3*8+12, 115, 0x1FE5); 
	ST7735_FillRect(4+6*8, 4, 4+6*8+12, 115, 0x1FE5); 
}

void load_temp(uint8_t a, uint8_t b, uint8_t c){
	
	ST7735_FillRect(4+1, 4+1, 16-1, 114-a, 0x1FE5); 	
	ST7735_FillRect(4+1, 114-a, 16-1, 114, 0xF841); 
	
	ST7735_FillRect(4+3*8+1, 4+1, 4+3*8+12-1, 114-b, 0x1FE5); 
	ST7735_FillRect(4+3*8+1, 114-b, 4+3*8+12-1, 114, 0xF841); 
	
	ST7735_FillRect(4+6*8+1, 4+1, 4+6*8+12-1, 114-c, 0x1FE5); 
	ST7735_FillRect(4+6*8+1, 114-c, 4+6*8+12-1, 114, 0xF841); 

	ST7735_FillRect(4+8*8, 64, 4+8*8+12, 64 + a, 0x08DF);
	ST7735_FillRect(4+8*8, 64 + a+1, 4+8*8+12, 64 + 63, 0x0000);
}

void uart_1_init(void){
	/* pa9 - pa10 */
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRH &=~ 0x00000FF0;
	GPIOA->CRH |= (B1010<<4)|(B0100<<8);
	
	RCC->APB2ENR |= (1<<14);
	USART1->CR1 &=~ (1<<12);
	USART1->CR1 &=~ (1<<9);
	USART1->CR1 |= (1<<2);
	USART1->CR1 |= (1<<3);
	
	USART1->BRR = 0x0271;
	USART1->CR1 |= (1<<13);
	USART1->CR1 |= (1<<5);
	// 37/4 = 9, 1*8 = 8
	NVIC->IP[9] = (0<<8);
	// 37/32 = 1, 37-32 = 5
	NVIC->ISER[1] = (1<<5);
}

#define LEN_BUFF 32
uint8_t _rx_buffer[LEN_BUFF];
volatile uint16_t _head = 0;

#define CHUA_CO_GI 0
#define NHAN_XONG  1
uint8_t status = CHUA_CO_GI;

void USART1_IRQHandler(void) {
	if( (USART1->SR & (1<<5)) && (USART1->CR1 & (1<<5))){
		if (status == CHUA_CO_GI){
			uint8_t data = USART1->DR;
			if ((data==':') && (_head == 0)){
				_head = 1;
				return;
			}
			else if ((data!=':') && (_head >= 1)){
				if (data != (uint8_t)'\r'){
					_rx_buffer[_head-1] = data;
					_head+=1;
				}
				else{
					status = NHAN_XONG;
					_head = 0;
				}
			}
		}
	}
	USART1->SR &=~ (1<<5);
}

static uint8_t cvt_to_hex(uint8_t d_ascii) {
  if (('0' <= d_ascii) && (d_ascii <= '9'))
    return (d_ascii - 48);
  else if (('a' <= d_ascii) && (d_ascii <= 'f'))
    return (d_ascii - 87);
  else if (('A' <= d_ascii) && (d_ascii <= 'F'))
    return (d_ascii - 55);
  return 0x00;
}

extern void setup(void){
	gui_main();
	uart_1_init();
}

uint8_t serial_temp_1 = 0;
uint8_t serial_temp_2 = 0;
uint8_t serial_temp_3 = 0;

uint16_t i_q = 0;
uint16_t i_d = 0;

uint8_t len_text_data = 0;
char text_data[LEN_BUFF] = {0};

uint8_t i_q_len = 0;
char i_q_text[LEN_BUFF] = {0};

uint8_t i_d_len = 0;
char i_d_text[LEN_BUFF] = {0};

extern void loop(void){
	if (status == NHAN_XONG){
		serial_temp_1 = cvt_to_hex(_rx_buffer[0])*16 + cvt_to_hex(_rx_buffer[1]);
		serial_temp_2 = cvt_to_hex(_rx_buffer[2])*16 + cvt_to_hex(_rx_buffer[3]);
		serial_temp_3 = cvt_to_hex(_rx_buffer[4])*16 + cvt_to_hex(_rx_buffer[5]);
		
		i_q = (cvt_to_hex(_rx_buffer[7])*16 + cvt_to_hex(_rx_buffer[6]))*256;
		i_q += cvt_to_hex(_rx_buffer[9])*16 + cvt_to_hex(_rx_buffer[8]);
		
		i_d = (cvt_to_hex(_rx_buffer[10])*16 + cvt_to_hex(_rx_buffer[11]))*256;
		i_d += cvt_to_hex(_rx_buffer[12])*16 + cvt_to_hex(_rx_buffer[13]);
	
		len_text_data = sprintf(text_data, "%3d %3d %3d",serial_temp_1, serial_temp_2, serial_temp_3);
		
		i_q_len = sprintf(i_q_text, "%4d",i_q);
		i_d_len = sprintf(i_d_text, "%4d",i_d);
		
		status = CHUA_CO_GI;
	}
	load_temp(serial_temp_1,serial_temp_2,serial_temp_3);
	ST7735_PutStr5x7(0,120,text_data, 0xFA83);
	ST7735_PutStr5x7(92,64,i_q_text, 0xFA83);
//	ST7735_PutStr5x7(0,120,text_data, 0xFA83);
}
