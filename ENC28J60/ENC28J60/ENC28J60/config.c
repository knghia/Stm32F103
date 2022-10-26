
#include "config.h"

void enc28j60_CS_low(void){
	GPIOA->ODR &=~ (1 << 4);
}

void enc28j60_CS_high(void){
	GPIOA->ODR |= (1 << 4);
}

void enc28j60_RST_low(void){
	GPIOA->ODR &=~ (1 << 3);
}

void enc28j60_RST_high(void){
	GPIOA->ODR |= (1 << 3);
}

void enc28j60_spi_init(void){
  /* Enable GPIOA */
  RCC->APB2ENR |= (1<<2);
  /* 
		MOSI - PA7
		MISO - PA6
		SCK - PA5
		SS - PA4
		RST - PA3
	 */
  GPIOA->CRL &=~ 0xFFFFF000;
  GPIOA->CRL |=  0x98911000;
	enc28j60_RST_high();
  /* SPI Config */
	
	/* Enable SPI1 CLock */
  RCC->APB2ENR |= (1<<12);
	/* CPOL=0, CPHA=0 */
  SPI1->CR1 &=~ (3<<0);
	/* Master Mode */
  SPI1->CR1 |= (1<<2);
	/* BR[2:0] = 011: fPCLK/16, PCLK2 = 72MHz, SPI clk = 4.2MHz */
  SPI1->CR1 |= (3<<3);
	/* MSB first */
  SPI1->CR1 &= ~(1<<7);
	/* SSM=1, SSi=1 -> Software Slave Management */
  SPI1->CR1 |= (1<<8) | (1<<9);
	/* RXONLY = 0, full-duplex */
  SPI1->CR1 &= ~(1<<10);
	/* DFF=0, 8 bit data */
  SPI1->CR1 &= ~(1<<11);
  SPI1->CR2 = 0;
	/* SPI2 enabled */
  SPI1->CR1 |= (1<<6);
}

void enc28j60_spi_write(uint8_t data){
	SPI1->DR = data;
  while (!SPI1->SR&(1<<1));
  while (SPI1->SR&(1<<7));
	uint16_t dummy = SPI1->DR;
	dummy = SPI1->SR;
}

uint8_t enc28j60_spi_read(void){
	while (SPI1->SR&(1<<7));
	SPI1->DR = 0;
  while (!SPI1->SR&(1<<0));
	uint16_t dummy = SPI1->SR;
	dummy = SPI1->DR;
	return dummy;
}


