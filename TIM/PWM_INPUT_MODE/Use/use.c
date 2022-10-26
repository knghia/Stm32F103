#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void tim_1_init(void){
	// Enable clock GPIOA : alternate function
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRH &=~ 0x0000000F;
	GPIOA->CRH |= 0x0000000B;
	
	// Enable tim 1 
	RCC->APB2ENR |= (1<<11);
	TIM1->CNT = 0;
	TIM1->PSC = 0;
	TIM1->ARR = 3599;
	
	// Center-aligned mode 1
	TIM1->CR1 |= (1<<5);
	// PWM Mode 1 : CHANNEL 1
	TIM1->CCMR1 |= (B110<<4)|(1<<3);

	// Capture/Compare 1 output polarity
	TIM1->CCER |= (1<<0)|(1<<1);

	// enable tim 1
  TIM1->BDTR |= (1<<15)|(1<<13);
	TIM1->CR1 |= (1<<0);
	
	TIM1->CCR1 = 500;
}


void tim2_pwm_input_mode(void){
	RCC->APB1ENR |= (1<<0);
	
	TIM2->CNT = 0;
	TIM2->PSC = 0;
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
	tim_1_init();
	tim2_pwm_input_mode();
}

#define LED_ON() 	{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() {GPIOC->ODR |= (1<<13);}

uint16_t period = 0;
uint16_t duty = 0;

extern void loop(void){
	period = TIM2->CCR2;
	duty = TIM2->CCR1;
}



