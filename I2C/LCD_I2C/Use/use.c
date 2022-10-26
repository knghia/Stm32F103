
#include "use.h"
#include "i2c.h"
#include "pcf8574.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

extern void setup(void){
	i2c_lcd4_init();
  i2c_lcd4_puts("hello");
	i2c_lcd4_cursor(1,0);
	i2c_lcd_print_number(1234,10);
}

#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define LED_ON() {GPIOC->ODR &=~ (1<<13);}

extern void loop(void){

	LED_OFF();
	HAL_Delay(250);
	LED_ON();
	HAL_Delay(250);
}
