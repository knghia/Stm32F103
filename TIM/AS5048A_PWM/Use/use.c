
#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void tim2_pwm_input_mode(void){
	RCC->APB1ENR |= (1<<0);
	
	TIM2->CNT = 0;
	TIM2->PSC = 15;
	TIM2->ARR = 0xFFFF;
	
	/* CC1 channel is configured as input, IC1 is mapped on TI1 */
	TIM2->CCMR1 |= (B01<<0);
	/* Capture is done on a rising edge of IC1 */
	TIM2->CCER &=~ (1<<1);
	
	/* CC2 channel is configured as input, IC2 is mapped on TI1 */
	TIM2->CCMR1 |= (B10<<8);
	/* Capture is done on a falling edge of IC2 */
	TIM2->CCER |= (1<<5);

	/* Trigger selection :  TI1 Edge Detector */
	TIM2->SMCR |= (B101<<4);
	/* Slave mode selection : Reset mode */
	TIM2->SMCR |= (B100<<0);

	/* Capture 1,2 enabled */
	TIM2->CCER |= (1<<0)|(1<<4);
	
	TIM2->CCR1 = 0;
	TIM2->CCR2 = 0;
	TIM2->CR1 |= (1<<0);
}

extern void setup(void){
	gpio_init();
	tim2_pwm_input_mode();
}

#define LED_ON() 	{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() {GPIOC->ODR |= (1<<13);}

uint16_t ccr2 = 0;
uint16_t ccr1 = 0;

uint16_t data;

float angle = 0;

#define SCALER 72e+6

extern void loop(void){
	ccr2 = TIM2->CCR2;
	ccr1 = TIM2->CCR1;
	
	data = ccr2-12;
	angle = data/(float)4096;
}



