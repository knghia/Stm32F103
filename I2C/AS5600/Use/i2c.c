#include "i2c.h"

uint16_t status;

extern void i2c_init(void)
{
	/*
	PB6, PB7:
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
	HAL_Delay(200);
}

extern void i2c_write(uint8_t address, uint8_t byte)
{
	// create start condition
	I2C1->CR1 |= (1<<8);
	// EV5 : check Start condition generated
	while(!(I2C1->SR1 & (1<<0)));
	status = I2C1->SR1;
	I2C1->DR = address<<1;
	
	// EV6: Received address matched
	while(!(I2C1->SR1 & (1<<1)));
	status = I2C1->SR1;
	status = I2C1->SR2;
	
	// EV8_1: write data DR
	while(!(I2C1->SR1 & (1<<7)));
	I2C1->DR = byte;
	
	while(!(I2C1->SR1 & (1<<7)));
	while(!(I2C1->SR1 & (1<<2)));
	
	// EV8_2: create stop condition
	I2C1->CR1 |= (1<<9);
	status = I2C1->SR1;
	status = I2C1->SR2;
}

extern uint16_t i2c_read(uint8_t address, uint8_t address_of_register)
{
	uint8_t data_h, data_l;
	
	// create start condition
	I2C1->CR1 |= (1<<8);
	// EV5 : check Start condition generated
	while(!(I2C1->SR1 & (1<<0)));
	status = I2C1->SR1;
	// address for write
	I2C1->DR = address<<1;
	
	// EV6: Received address matched
	while(!(I2C1->SR1 & (1<<1)));
	status = I2C1->SR1;
	status = I2C1->SR2;
	
	// EV8_1: write data DR
	while(!(I2C1->SR1 & (1<<7)));
	I2C1->DR = address_of_register;
	
	while(!(I2C1->SR1 & (1<<7)));
	while(!(I2C1->SR1 & (1<<2)));
	
	// create Restart condition
	I2C1->CR1 |= (1<<8);
	// EV5 : check Restart condition generated
	while(!(I2C1->SR1 & (1<<0)));
	status = I2C1->SR1;
	// address for read
	I2C1->DR = (address<<1)+1;
	
	// EV6: Received address matched
	while(!(I2C1->SR1 & (1<<1)));
	status = I2C1->SR1;
	status = I2C1->SR2;
	
	while(!(I2C1->SR1 & (1<<6)));
	data_h = I2C1->DR;
	while(!(I2C1->SR1 & (1<<6)));
	data_l = I2C1->DR;
	
	// No acknowledge returned
	I2C1->CR1 &=~ (1<<10);
	// EV8_2: create stop condition
	I2C1->CR1 |= (1<<9);
	status = I2C1->SR1;
	status = I2C1->SR2;
	
	return (data_h*256 + data_l);
}










