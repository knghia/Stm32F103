#include <stdio.h>
#include "use.h"
#include "binary.h"
#include "st7735.h"
#include "st7735_graphics.h"
#include "st7735_text.h"

#define MAX_LEN 130
uint8_t temp_1[MAX_LEN] = {0};
uint8_t temp_2[MAX_LEN] = {0};
uint8_t temp_3[MAX_LEN] = {0};
uint8_t index_temp = 0;

void ssd1306_clear_graphic(void){
	int i,j;
	for(i=29;i<128;i++){
		for(j=29;j<160;j++){
			ST7735_Pixel(i,j,RGB565(0, 0, 0));
		}
	}
}

void reload_array_temp(void){
	uint8_t i;
	if (index_temp == MAX_LEN){
		ssd1306_clear_graphic();
		for(i=0;i<MAX_LEN;i++){
			if (i+25 >= MAX_LEN){
				temp_1[i] = 0;
				temp_2[i] = 0;
				temp_3[i] = 0;
			}
			else{
				temp_1[i] = temp_1[i+25];
				temp_2[i] = temp_2[i+25];
				temp_3[i] = temp_3[i+25];
			}
		}
		index_temp = MAX_LEN-25;
	}
	for(i=0;i<index_temp-1;i++){
		ST7735_Line(temp_1[i]+29,i+29,temp_1[i+1]+29,i+30,0xFFFF);
//		ST7735_Line(temp_2[i]+29,i+29,temp_2[i+1]+29,i+30,0xFFE0);
//		ST7735_Line(temp_3[i]+29,i+29,temp_3[i+1]+29,i+30,0xF81F);
	}
	
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

static void gui_main(){
	ST7735_Init();
	ST7735_Clear(0x0000);
	
	// ST7735_PutStr5x7(10, 10, "nghia", RGB565(236, 252, 3));
	ST7735_Line(28,28,28,159,RGB565(0, 255, 0));
	ST7735_Line(27,28,27,159,RGB565(0, 255, 0));
	
	ST7735_Line(28,28,127,28,RGB565(0, 255, 0));
	ST7735_Line(28,27,127,27,RGB565(0, 255, 0));

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

uint8_t len_text_data = 0;
char text_data[LEN_BUFF] = {0};

extern void loop(void){
	if (status == NHAN_XONG){
		serial_temp_1 = cvt_to_hex(_rx_buffer[0])*16 + cvt_to_hex(_rx_buffer[1]);
		serial_temp_2 = cvt_to_hex(_rx_buffer[2])*16 + cvt_to_hex(_rx_buffer[3]);
		serial_temp_3 = cvt_to_hex(_rx_buffer[4])*16 + cvt_to_hex(_rx_buffer[5]);

		len_text_data = sprintf(text_data, "%3d %3d %3d",serial_temp_1, serial_temp_2, serial_temp_3);
		status = CHUA_CO_GI;
	}
	temp_1[index_temp] = serial_temp_1;
	temp_2[index_temp] = serial_temp_2;
	temp_3[index_temp] = serial_temp_3;
	index_temp+=1;
	reload_array_temp();
	ST7735_PutStr5x7(7,0,text_data, 0xFA83);
}
