#include "config.h"

void tft18_gpio_init(void){
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRH &=~ 0x000000FF;
	GPIOA->CRH |= 0x00000011;
}

void tft18_spi_init(void){
	// Enable SPI2 CLock
  RCC->APB1ENR |= (1<<14);
  // Enable GPIOB 
  RCC->APB2ENR |= (1<<3);
  // MOSI - PB15; SCK - PB13; SS - PB12
  GPIOB->CRH &=~ 0xF0FF0000;
  GPIOB->CRH |=  0x90910000;
  // SPI Config
	
  SPI2->CR1 &=~ (3<<0);     // CPOL=0, CPHA=0
  SPI2->CR1 |= (1<<2);            // Master Mode
//   SPI2->CR1 |= (1<<14);           // Transmit Only
//   SPI2->CR1 |= (1<<15);           // 1 line
  SPI2->CR1 |= (3<<3);            // BR[2:0] = 011: fPCLK/16, PCLK2 = 72MHz, SPI clk = 4.2MHz
  SPI2->CR1 &= ~(1<<7);           // LSBFIRST = 0, MSB first
  SPI2->CR1 |= (1<<8) | (1<<9);   // SSM=1, SSi=1 -> Software Slave Management
  SPI2->CR1 &= ~(1<<10);          // RXONLY = 0, full-duplex
  SPI2->CR1 &= ~(1<<11);          // DFF=0, 8 bit data
  SPI2->CR2 = 0;
  SPI2->CR1 |= (1<<6);            // SPI2 enabled
}

void tft18_spi_write(uint8_t data){
	SPI2->DR = data;
  while (!SPI2->SR&(1<<1)) {}
  while (SPI2->SR&(1<<7)) {}
}

void tft18_CS_low(void){
	GPIOB->ODR &=~ (1 << 12);
}

void tft18_CS_high(void){
	GPIOB->ODR |= (1 << 12);
}

void tft18_AO_low(void){
	GPIOA->ODR &=~ (1 << 9);
}

void tft18_AO_high(void){
	GPIOA->ODR |= (1 << 9);
}

void tft18_RST_low(void){
	GPIOA->ODR &=~ (1 << 8);
}

void tft18_RST_high(void){
	GPIOA->ODR |= (1 << 8);
}
