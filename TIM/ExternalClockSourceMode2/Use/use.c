#include "use.h"

void gpio_init(void){
	/* Enable clock GPIOC */
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00600000;
}

void tim_1_init(void){
	/* 0. Enable cleck tim 1  */
	RCC->APB2ENR |= (1<<11);
	/* 1. Setup */
	TIM1->CNT = 0;
	TIM1->PSC = 72-1;
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

void tim_2_init(void){
	/* 0.PA0 - input floating */
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRL &=~ 0x0000000F;
	GPIOA->CRL |= 0x00000004;
	
	/* Time 2: External clock source mode 2 */
	
	/* Normal setup */
	RCC->APB1ENR |= (1<<0);
	TIM2->CNT = 0;
	TIM2->ARR = 50000-1;
	
	/* External clock source mode 2 */
	/* 1. As no filter : fDTS */
	TIM2->SMCR &=~ (7<<8);
	/* 2. Set the prescaler : Prescaler OFF */
	TIM2->SMCR &=~ (3<<12);
	/* 3. Select rising edge detection */
	TIM2->SMCR |= (1<<15);
	/* 4. Enable external clock mode 2 */
	TIM2->SMCR |= (1<<14);
	/* 5. Enable the counter */
	TIM2->SR = 0;
	TIM2->CR1 |= (1<<0);
}

extern void setup(void){
	gpio_init();
	tim_1_init();
	tim_2_init();
}

extern void loop(void){
}



