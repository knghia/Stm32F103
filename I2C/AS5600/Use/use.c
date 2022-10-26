
#include "use.h"
#include "i2c.h"
#include "as5600.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

extern void setup(void){
	as5600_init();

}

#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define LED_ON() {GPIOC->ODR &=~ (1<<13);}
#define LED_TOGGLE() {GPIOC->ODR ^= (1<<13);}

uint16_t raw_angle;
float angle = 0;

extern void loop(void){
	raw_angle = as5600_read(0x0C);
	
	angle = raw_angle * 0.087890625; 
}
