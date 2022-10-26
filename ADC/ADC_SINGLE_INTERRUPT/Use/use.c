
#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void adc_single(void){
	// 1. Enable clock GPIOA : ADC 1 PA6 ~ analog mode
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRL &=~ 0x0F000000;
	// 2. Enable clock adc 1
	RCC->APB2ENR |= (1<<9);
	// 3. Data Alignment RIGHT
	ADC1->CR2 &= ~(1<<11);
	// 4. sample time : 13.5
	ADC1->SMPR2 &=~(B111<<18);
	ADC1->SMPR2 |= (2<<18);
	
	// 5. External trigger conversion mode for regular channels
	ADC1->CR2 |= (1<<20);
	// 6. External event select for regular group
	ADC1->CR2 |= (B111<<17);
	
  // 7. Length convert = 1
	ADC1->SQR1 &=~(B1111<<20);
	ADC1->SQR1 |= (0<<20);
	
	// 8. Continuous conversion : singel mode
	ADC1->CR2 &=~ (1<<1);
	// 9. set index
	ADC1->SQR3 |= (6<<0);
	// 10. ADC Convert on 
	ADC1->CR2 |= (1<<0);
	// 11. ADC interrupt : End of conversion regular group
	ADC1->CR1 |= (1<<5);
	
	// NVIC : Number of interrupt adc is 18
	/* 
		Polarity
		18/4 = 4
		(18-4*4)= 2-> (2)*4 = 8
	*/
	NVIC->IP[4] = (0<<8);
	/*
		Enable
		18/32 = 0
		18-32*0= 18
	*/
	NVIC->ISER[0] = (1<<18);
	
	ADC1->DR = 0;
	ADC1->CR2 |= (1<<22);
}

volatile uint16_t adc_value;

void ADC1_IRQHandler(void)
{
	if ((ADC1->SR&(1<<1)) != 0){
		adc_value = (uint16_t)ADC1->DR;
		
	}
	ADC1->SR &=~ (1<<1);
	ADC1->DR = 0;
	ADC1->CR2 |= (1<<22);
}

#define LED_ON() 	{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define LED_TOGGLE() {GPIOC->ODR ^= (1<<13);}

extern void setup(void){
	gpio_init();
	adc_single();
}

extern void loop(void){
	LED_TOGGLE();
	HAL_Delay(500);
}





