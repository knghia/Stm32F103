#include "w5500_spi.h"

#define SS		4
#define RST		3

void W5500_CSL(void){
	GPIOA->ODR &=~ (1<<SS);
}

void W5500_CSH(void){
	GPIOA->ODR |= (1<<SS);
}

void W5500_RST_L(void){
	GPIOA->ODR &=~ (1<<RST);
}

void W5500_RST_H(void){
	GPIOA->ODR |= (1<<RST);
}

void W5500_SPI_Write(uint8_t data){
	HAL_SPI_Transmit(&hspi1, &data, 1, 100);
}

u08 W5500_SPI_Read(void){
	uint8_t c = 0;
	HAL_SPI_Receive(&hspi1, &c, 1, 100);
	return c;
}

void W5500_SPI_Write_Buff(u08* pBuf, u08 len){
	HAL_SPI_Transmit(&hspi1, pBuf, len, 100);
}

void W5500_SPI_Read_Buff(u08* pBuf, u08 len){
	HAL_SPI_Receive(&hspi1, pBuf, len, 100);
}

