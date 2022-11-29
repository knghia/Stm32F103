
#include "use.h"

#define LED_ON() 			{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() 		{GPIOC->ODR |= (1<<13);}
#define LED_TOGGLE() 	{GPIOC->ODR ^= (1<<13);}

void gpio_init(void){
	/* Enable clock GPIOC */
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void adc_single_continous(void){
	/* 1. Enable clock GPIOA : ADC 1 PA6 ~ analog mode */
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRL &=~ 0xF0000000;
	/* 2. Enable clock adc 1 */
	RCC->APB2ENR |= (1<<9);
	/* 3. Data Alignment RIGHT */
	ADC1->CR2 &= ~(1<<11);
	/* 4. sample time : 13.5 */
	ADC1->SMPR2 |= (2<<18);
  /* 5. Length convert = 1 */
	ADC1->SQR1 |= (0<<20);
	/* 6. Continuous conversion mode */
	ADC1->CR2 |= (1<<1);
	/* 7. Set index */
	ADC1->SQR3 |= (6<<0);
	/* 8. ADC EOCIE interrupt enable */
	ADC1->CR1 |= (1<<5);
	NVIC_SetPriority(ADC1_IRQn, 0);
	NVIC_EnableIRQ(ADC1_IRQn);
	/* 9. ADC Convert ON */
	ADC1->CR2 |= (1<<0);
	
	/* 10. External trigger conversion mode for regular channels */
	ADC1->CR2 |= (1<<20);
	/* 11. External event select for regular group */
	ADC1->CR2 |= (B111<<17);
	/* 12. Start conversion */
	ADC1->CR2 |= (1<<22);
}

u16 adc_value = 0;

void ADC1_2_IRQHandler(void){
	if (ADC1->CR1&(1<<5)){
		if (ADC1->SR&(1<<1)){
			adc_value = ADC1->DR;
		}
	}
}

extern void setup(void){
	gpio_init();
	adc_single_continous();
}


extern void loop(void){
	printf("adc %d \r\n", adc_value);
}



