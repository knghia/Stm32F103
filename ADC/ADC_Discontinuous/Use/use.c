
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

void adc_discontinous(void){
	/* 1. Enable clock GPIOA */
	/* ADC 1 PA6, PA7 ~ analog mode */
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRL &=~ 0xFF000000;
	/* 2. Enable clock adc 1 */
	RCC->APB2ENR |= (1<<9);
	/* 3. Data Alignment RIGHT */
	ADC1->CR2 &= ~(1<<11);
	/* 4. sample time : 13.5 */
	ADC1->SMPR2 |= (2<<18);
	
	/* 5. Discontinuous mode */
	ADC1->CR1 |= (1<<11);
	/* 6. Scan mode */
	ADC1->CR1 |= (1<<8);
	/* 7. Discontinuous mode number : 1 */
	ADC1->CR1 |= (0<<13);
  /* 8. Length convert = 2 */
	ADC1->SQR1 |= (1<<20);
	/* 9. Set index */ADC1->CR2 |= (1<<22);
	ADC1->SQR3 = (6<<0)|(7<<5);
	
	
	/* 10. External trigger conversion mode for regular channels */
	ADC1->CR2 |= (1<<20);
	/* 11. External event select for regular group */
	ADC1->CR2 |= (B111<<17);
	
	/* 12. ADC Convert on */
	ADC1->CR2 |= (1<<0);
	/* 13. Start conversion */
	ADC1->CR2 |= (1<<22);
}

u16 read_adc(void){
	ADC1->CR2 &=~ (1<<22);
	ADC1->CR2 |= (1<<22);
	HAL_Delay(1);
	while(!(ADC1->SR&(1<<1)));
	return ADC1->DR;
}

u16 adc_a, adc_b = 0;

extern void setup(void){
	gpio_init();
	adc_discontinous();
}


extern void loop(void){
	adc_a = read_adc();
	adc_b = read_adc();
	printf("adc %d %d \r\n", adc_a, adc_b);
}



