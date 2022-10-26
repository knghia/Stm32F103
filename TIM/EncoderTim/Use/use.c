
#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}


extern void setup(void){
	gpio_init();
	
	/*
		Enable clock GPIOA : 
			+ Alternate function PA6,PA7
			+ Tim 3 encoder
	*/
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRL &=~ 0xFF000000;
	GPIOA->CRL |= 0x44000000;
	
	// 1. Enable clock tim 3 
	RCC->APB1ENR |= (1<<1);
	// 2. Encoder mode  TI1FP1, TI2FP2
	TIM3->SMCR |= (B011<<0);
	// 3. TI1, TI2 select porarity : non invert
	TIM3->CCER &=~ (1<<1)|(1<<5);

	TIM3->CNT = 0;
	TIM3->PSC = 0;
	TIM3->ARR = 0xFFFF;
	
	// Enable tim 3
	TIM3->CR1 |= (1<<0);
	// Enable interrupt tim 3
	TIM3->DIER |= (1<<0);
	
	/* 
		NVIC TIM 3 update : 29
		29/4 = 7
		(29-4*7)= 1-> (1)*8 = 8
	*/
	NVIC->IP[7] = (0<<8);
	/* 
		NVIC TIM 3 update : enable
		29/31 = 0
		29-31*0= 29
	*/
	NVIC->ISER[0] = (1<<29);
}

#define LED_ON() 	{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define LED_TOGGLE() {GPIOC->ODR ^= (1<<13);}
#define _2PI 6.28318530718f

int32_t time_of_count = 0;
int32_t count = 0;

void TIM3_IRQHandler(void)
{
	if (TIM3->SR &(1<<0)){
		if (TIM3->CR1 & (1<<4)){
			time_of_count -= 1;
		}
		else{
			time_of_count += 1;
		}
	}
	TIM3->SR &=~ (1<<0);
}

float angle = 0;
extern void loop(void){
	count = TIM3->CNT;
	count += time_of_count*65535;
	
	angle = count/(float)2400*_2PI;
}

