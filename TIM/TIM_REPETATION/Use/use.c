#include "use.h"

void gpio_init(void){
	/* Enable clock GPIOC */
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= (B0110<<20);
}

void tim_1_init(void){
	/* 0. Enable cleck tim 1  */
	RCC->APB2ENR |= (1<<11);
	/* 1. Setup */
	TIM1->CNT = 0;
	TIM1->PSC = 720-1;
	TIM1->ARR = 50000-1;
	/* 2. Repetation */
	TIM1->RCR = 8;
	/* 3. Update interrupt enable */
	TIM1->DIER |= (1<<0);
	/* 4. Clean all statuses of the time */
	TIM1->SR = 0;
	/* 
		NVIC TIM 1 update : 25
		25/4 = 6
		(25-4*6)= 1-> (1)*8 = 8
	*/
	NVIC->IP[6] = (0<<8);
	/* 
		NVIC TIM 1 update : enable
		25/32 = 0
		25-32*0= 25
	*/
	NVIC->ISER[0] = (1<<25);
	/* 5. Enable time 1 */
	TIM1->SR = 0;
	TIM1->CR1 |= (1<<0);
}

#define LED_TOGGLE() {GPIOC->ODR ^= (1<<13);}

void TIM1_UP_IRQHandler(void)
{
	if (TIM1->SR & (1<<0))
	{
		LED_TOGGLE();
	}
	TIM1->SR &=~ (1<<0);
}


extern void setup(void){
	gpio_init();
	tim_1_init();
}

extern void loop(void){
}



