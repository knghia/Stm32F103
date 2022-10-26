
#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void pwm_init(void){
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

	// Capture/Compare 1 output polarity
	TIM1->DIER |= (1<<0);
	
	// enable tim 1
	TIM1->BDTR |= (1<<15)|(1<<13);
	TIM1->CR1 |= (1<<0);
	TIM1->CCR1 = 1000;
	
	/* 
		NVIC TIM 1 update : 25
		25/4 = 6
		(25-4*6)= 1-> (1)*8 = 8
	*/
	NVIC->IP[6] = (0<<8);
	/* 
		NVIC TIM 1 update : enable
		25/31 = 0
		25-31*0= 25
	*/
	NVIC->ISER[0] = (1<<25);
}

#define LED_ON() 	{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define LED_TOGGLE() {GPIOC->ODR ^= (1<<13);}

void TIM1_IRQHandler(void)
{
	if (TIM1->SR & (1<<0))
	{
		LED_TOGGLE();
	}
}

extern void setup(void){
	gpio_init();
	pwm_init();
}

extern void loop(void){
	LED_ON();
	HAL_Delay(500);
	LED_OFF();
	HAL_Delay(500);
}
