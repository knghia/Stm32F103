#include "use.h"

void gpio_init(void){
	/* Enable clock GPIOC */
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void tim_1_init(void){
	/* Enable clock GPIOA : alternate function PA8 */
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRH &=~ 0x0000000F;
	GPIOA->CRH |= 0x0000000B;
	/* Enable tim 1 */
	RCC->APB2ENR |= (1<<11);
	TIM1->CNT = 0;
	TIM1->PSC = 0;
	TIM1->ARR = 3599;
	
	/* PWM Mode 1 */
	TIM1->CCMR1 |= (B110<<4);
	/*  Output compare 1 preload: disable */
	TIM1->CCMR1 &=~ (1<<3);
	/* Capture/Compare 1 output polarity */
	TIM1->CCER &=~ (1<<1);
	/* Capture/Compare 1 output enable */
	TIM1->CCER |= (1<<0);
	/* Enable tim 1 */
	TIM1->BDTR |= (1<<15);
	TIM1->CR1 |= (1<<0);
	TIM1->CCR1 = 1000;
}


void tim2_pwm_input_mode(void){
	/* 0.PA0 - input floating */
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRL &=~ 0x0000000F;
	GPIOA->CRL |= 0x00000004;
	
	RCC->APB1ENR |= (1<<0);
	TIM2->CNT = 0;
	TIM2->PSC = 0;
	TIM2->ARR = 0xFFFF;

	/* TIM2 : pwm input mode P315*/

	/* 1. Select the active input */
	/* CC1 channel is configured as input, IC1 is mapped on TI1 */
	TIM2->CCMR1 |= (B01<<0);
	/* 2. Select the active polarity : active on rising edge */
	TIM2->CCER &=~ (1<<1); // - for TIM2_CCR1
	/* 3. Select the active input */
	TIM2->CCMR1 |= (B10<<8);
	/* 4. Select the active polarity : active on falling edge */
	TIM2->CCER |= (1<<5); // - for TIM2_CCR2
	/* 5. Select the valid trigger input  */
	TIM2->SMCR |= (B101<<4);
	/* 6. Configure the slave mode controller in the reset mode  */
	TIM2->SMCR |= (B100<<0);
	/* 7. Capture 1,2 enabled */
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
	duty = TIM2->CCR2;
	period = TIM2->CCR1;
}



