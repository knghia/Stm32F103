
#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void tim_2_init(void){
	// 0. Enable clock tim 2
	RCC->APB1ENR |= (1<<0);
	TIM2->CNT = 0;
	TIM2->PSC = 35;
	TIM2->ARR = 999;
	// 1. Enable UDIS tim 2
	TIM2->CR1 &=~	(1<<1);
	// 2. Update interrupt enable
	TIM2->DIER |= (1<<0);
	// Enable time 1
	TIM2->BDTR |= (1<<15)|(1<<13); 
	TIM2->CR1 |= (1<<0);
	/* 
		NVIC TIM 2 update : 25
		28/4 = 7
		(28-4*7)= 0-> (0)*8 = 8
	*/
	NVIC->IP[6] = (0<<0);
	/* 
		NVIC TIM 1 update : enable
		28/31 = 0
		28-31*0= 28
	*/
	NVIC->ISER[0] = (1<<28);
}

#define LED_TOGGLE() {GPIOC->ODR ^= (1<<13);}

void TIM2_IRQHandler(void)
{
	if (TIM2->SR & (1<<0))
	{
		LED_TOGGLE();
	}
	TIM2->SR &=~ (1<<0);
}


extern void setup(void){
	gpio_init();
	tim_2_init();
}

#define LED_ON() 	{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() {GPIOC->ODR |= (1<<13);}

extern void loop(void){
}