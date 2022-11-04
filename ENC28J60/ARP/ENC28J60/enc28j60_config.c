#include "binary.h"
#include "enc28j60_config.h"

#define SS		4
#define RST		3

void enc28j60_CS_low(void){
	GPIOA->ODR &=~ (1<<SS);
}

void enc28j60_CS_high(void){
	GPIOA->ODR |= (1<<SS);
}

void enc28j60_RST_low(void){
	GPIOA->ODR &=~ (1<<RST);
}

void enc28j60_RST_high(void){
	GPIOA->ODR |= (1<<RST);
}

void enc28j60_spi_init(void){
}

void enc28j60_spi_write(uint8_t data){
	HAL_SPI_Transmit(&hspi1, &data, 1, 100);
}

uint8_t enc28j60_spi_read(void){
	uint8_t data;
	HAL_SPI_Receive(&hspi1, &data, 1, 100);
	return data;
}

extern void enc28j60_write_cmd(uint8_t opcode, uint8_t address, uint8_t data){
	address = opcode|(address&0x1F);
	enc28j60_CS_low();
	enc28j60_spi_write(address);
	enc28j60_spi_write(data);
	enc28j60_CS_high();
}

extern uint8_t enc28j60_read_cmd(uint8_t opcode, uint8_t address){
	uint8_t result = 0;
	address = opcode|(address&0x1F);
	enc28j60_CS_low();
	enc28j60_spi_write(address);
	result = enc28j60_spi_read();
	enc28j60_CS_high();
	return result;
}

