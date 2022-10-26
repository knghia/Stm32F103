
#include "config.h"


void st7735_gpio_init(void){
	/* config A0, RST */
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRL &=~ 0x0000FF00;
	GPIOA->CRL |= 0x00001100;
}

void st7735_spi_init(void){
	/* Enable SPI1 CLock */
  RCC->APB2ENR |= (1<<12);
  /* Enable GPIOA  */
  RCC->APB2ENR |= (1<<2);
  /* MOSI - PA7; SCK - PA5; SS - PA4 */
  GPIOA->CRL &=~ 0xF0FF0000;
  GPIOA->CRL |=  0x90910000;
  /* SPI 1 Config */
  SPI1->CR1 &=~ (3<<0);     			// CPOL=0, CPHA=0
  SPI1->CR1 |= (1<<2);            // Master Mode
  SPI1->CR1 |= (3<<3);            // BR[2:0] = 011: fPCLK/16, PCLK2 = 72MHz, SPI clk = 4.2MHz
  SPI1->CR1 &= ~(1<<7);           // LSBFIRST = 0, MSB first
  SPI1->CR1 |= (1<<8) | (1<<9);   // SSM=1, SSi=1 -> Software Slave Management
  SPI1->CR1 &= ~(1<<10);          // RXONLY = 0, full-duplex
  SPI1->CR1 &= ~(1<<11);          // DFF=0, 8 bit data
  SPI1->CR2 = 0;
  SPI1->CR1 |= (1<<6);            // SPI2 enabled
}

void st7735_spi_write(uint8_t data){
	SPI1->DR = data;
  while (!SPI1->SR&(1<<1)) {}
  while (SPI1->SR&(1<<7)) {}
}

void st7735_CS_low(void){
	GPIOA->ODR &=~ (1 << 4);
}

void st7735_CS_high(void){
	GPIOA->ODR |= (1 << 4);
}

void st7735_AO_low(void){
	GPIOA->ODR &=~ (1 << 3);
}

void st7735_AO_high(void){
	GPIOA->ODR |= (1 << 3);
}

void st7735_RST_low(void){
	GPIOA->ODR &=~ (1 << 2);
}

void st7735_RST_high(void){
	GPIOA->ODR |= (1 << 2);
}
