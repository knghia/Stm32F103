#include "i2c.h"

int16_t status;

extern void i2c_init(void)
{
	/*
	PB6, PB7: SCK, SDA
	*/
	
	// GPIOB clock enable
	RCC->APB2ENR |= (1<<3);
	GPIOB->CRL &=~ 0xFF000000;
	GPIOB->CRL |= 0x99000000;
	// 1. I2C 1 clock enable : 36MHz
	RCC->APB1ENR |= (1<<21);
	// 2. Peripheral clock frequency : 20Mhz
	I2C1->CR2 |= (20<<0);
	// 3. I2c mode
	I2C1->CR1 &=~ (1<<1);
	// 4. I2c Sm mode (max 100Khz)
	I2C1->CCR &=~ (1<<15);
	// 5. I2c Sm mode (max 100Khz)
	/*
		FREQ = 20Mhz
		(1/100K/2)/(1/20M) = 100
	*/
	I2C1->CCR |= (100<<0);
	// 6. I2c Maximum rise time 
	I2C1->TRISE |= (101<<0);
	
	// 7. Peripheral enable
	I2C1->CR1 |= (1<<0);
}

extern void i2c_write(uint8_t address, uint8_t byte)
{
	// create start condition
	I2C1->CR1 |= (1<<8);
	// EV5 : check Start condition generated
	while(! (I2C1->SR1 & (1<<0)));
	status = I2C1->SR1;
	I2C1->DR = address;
	
	// EV6: ADDR = 1 : End of address transmission
	while(! (I2C1->SR1 & (1<<1)));
	status = I2C1->SR1;
	status = I2C1->SR2;
	
	// EV8_1: write data DR
	while(! (I2C1->SR1 & (1<<7)));
	I2C1->DR = byte;
	
	while(! (I2C1->SR1 & (1<<7)));
	while(! (I2C1->SR1 & (1<<2)));
	
	// EV8_2: create stop condition
	I2C1->CR1 |= (1<<9);
	status = I2C1->SR1;
	status = I2C1->SR2;
}
