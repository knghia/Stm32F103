#include "binary.h"
#include "spi.h"
#include "main.h"

#define SS		4
#define RST		3

void ENC28J60_CSL(void){
	GPIOA->ODR &=~ (1<<SS);
}

void ENC28J60_CSH(void){
	GPIOA->ODR |= (1<<SS);
}

void ENC28J60_RST_L(void){
	GPIOA->ODR &=~ (1<<RST);
}

void ENC28J60_RST_H(void){
	GPIOA->ODR |= (1<<RST);
}

u08 SPI1_ReadWrite(uint8_t data){
	uint8_t c = 0;
	HAL_SPI_TransmitReceive(&hspi1, &data, &c, 1, 100);
	return c;
}

