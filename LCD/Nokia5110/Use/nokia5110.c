
#include "nokia5110.h"

/*
    MOSI - PB15
    MISO - PB14
		SCK - PB13
    CS - PB12
 */
#define SPI2_DISABLE()       {GPIOB->ODR |= (1 << 12);}
#define SPI2_ENABLE()      {GPIOB->ODR &=~ (1 << 12);}

extern void spi_init(void){
    
  // Enable SPI2 CLock
  RCC->APB1ENR |= (1<<14);
  // Enable GPIOB 
  RCC->APB2ENR |= (1<<3);
  // MOSI - PB15; MISO - PB14; SCK - PB13; SS - PB12
  GPIOB->CRH &=~ 0xFFFF0000;
  GPIOB->CRH |=  0x99910000;
  // SPI Config
	
  SPI2->CR1 &=~ (3<<0);     			// CPOL=0, CPHA=0
  SPI2->CR1 |= (1<<2);            // Master Mode
  SPI2->CR1 |= (3<<3);            // BR[2:0] = 011: fPCLK/16, PCLK2 = 72MHz, SPI clk = 4.2MHz
  SPI2->CR1 &= ~(1<<7);           // LSBFIRST = 0, MSB first
  SPI2->CR1 |= (1<<8) | (1<<9);   // SSM=1, SSi=1 -> Software Slave Management
  SPI2->CR1 &= ~(1<<10);          // RXONLY = 0, full-duplex
  SPI2->CR1 &= ~(1<<11);          // DFF=0, 8 bit data
  SPI2->CR2 = 0;
  SPI2->CR1 |= (1<<6);            // SPI2 enabled
}

extern void spi_write(uint8_t data){
  SPI2_ENABLE();
  SPI2->DR = data;
  while (!SPI2->SR&(1<<1)) {}
  while (SPI2->SR&(1<<7)) {}
  SPI2_DISABLE();
}

extern void spi_print(uint8_t* data,uint8_t len){
	uint8_t i = 0;
  SPI2_ENABLE();
	for(i=0;i<len;i++){
		SPI2->DR = data[i];
		while (!SPI2->SR&(1<<1)) {}
		while (SPI2->SR&(1<<7)) {}
	}
  SPI2_DISABLE();
}

/*
    RST - PA8
    DC - PA9
 */

#define RST_ON()       {GPIOA->ODR |= (1 << 8);}
#define RST_OFF()      {GPIOB->ODR &=~ (1 << 8);}

#define DC_ON()       	{GPIOA->ODR |= (1 << 9);}
#define DC_OFF()      	{GPIOB->ODR &=~ (1 << 9);}

extern void nokia5110_reset(void){
  RST_OFF();
  HAL_Delay(1);
  RST_ON();
}

extern void nokia5110_cmd(uint8_t cmd){
  DC_OFF();
  spi_write(cmd);
}

extern void nokia5110_write(uint8_t data){
  DC_ON();
  spi_write(data); 
}

extern void nokia5110_print(uint8_t *data,int len){
  DC_ON();
  spi_print(data,len);
}

extern void nokia5110_cursor(uint8_t row,uint8_t col){
  int i;
	i = row*84 + col;
	if (i < 0 || i > 503)
		return;
  nokia5110_cmd(0x80|col);  
  nokia5110_cmd(0x40|row);
}

extern void nokia5110_init(void){
	// Enable GPIOA 
  RCC->APB2ENR |= (1<<2);
	GPIOA->CRH &=~ 0x000000FF;
	GPIOA->CRH |= 0x00000011;
  
	spi_init();
  nokia5110_reset();
  nokia5110_cmd(0x21);
  nokia5110_cmd(0x13);
  nokia5110_cmd(0x07);
  nokia5110_cmd(0xc0);
  nokia5110_cmd(0x20);   
  nokia5110_cmd(0x0c);        
}

extern void nokia5110_text(uint8_t row,uint8_t col,char data){ 
	uint8_t buff,j;
  nokia5110_cursor(row,col);
	DC_ON();
	SPI2_ENABLE();

	for(j=0;j<6;j++){
		buff = AsciiForm[data-0x20][j];
    spi_write(buff);      
	}
	SPI2_DISABLE();   
}

extern void nokia5110_texts(uint8_t row,uint8_t col,char* data){ 
	uint8_t buff,j;
  nokia5110_cursor(row,col);
	DC_ON();
	SPI2_ENABLE();

	while(*data != 0){
		for(j=0;j<6;j++){
			buff = AsciiForm[*data-0x20][j];
			spi_write(buff);      
		}
		data++;
	}
	SPI2_DISABLE();   
}
