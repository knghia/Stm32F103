
#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void adc_single(void){
	/* 1. Enable clock GPIOA : ADC 1 PA6,PA7 ~ analog mode */
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRL &=~ 0xFF000000;
	/* 2. Enable clock adc 1 */
	RCC->APB2ENR |= (1<<9);
	/* 3. Data Alignment RIGHT */
	ADC1->CR2 &= ~(1<<11);
	/* 4. sample time : 13.5 */
	ADC1->SMPR2 |= (2<<18);
	/* 5. External trigger conversion mode for regular channels */
	ADC1->CR2 |= (1<<20);
	/* 6. External event select for regular group */
	ADC1->CR2 |= (B111<<17);
	/* 7. Continuous conversion : singel mode */
	ADC1->CR2 &=~ (1<<1);
	/* 8. ADC Convert on */
	ADC1->CR2 |= (1<<0);
	/* 9. ADC set index */
	ADC1->SQR3 = (6<<0);
	/* 10. ADC interrupt : End of conversion regular group */
	ADC1->CR1 |= (1<<5);
	/* NVIC :  18 */
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
}

//u16 read_adc(u08 ch){
//	ADC1->CR2 &=~ (1<<22);
//	ADC1->SR = 0;
//	ADC1->DR = 0;
//	ADC1->SQR3 = (ch<<0);
//	ADC1->CR2 |= (1<<22);
//	HAL_Delay(1);
//	while(ADC1->SR&(1<<1));
//	return ADC1->DR;
//}

void ADC1_2_IRQHandler(void){
	if (ADC1->CR1&(1<<5)){
		if (ADC1->SR&(1<<1)){
			if (ADC1->SQR3&(6<<0)){
				printf("6 \r\n");
				ADC1->SR &=~ (1<<1);
			}
		}
	}
}

u16 read_adc(void){
	ADC1->CR2 &=~ (1<<22);
	ADC1->SR = 0;
	ADC1->DR = 0;
	ADC1->CR2 |= (1<<22);
	while(!ADC1->SR&(1<<1));
	return ADC1->DR;
}

extern void setup(void){
	gpio_init();
	adc_single();
}

#define LED_ON() 			{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() 		{GPIOC->ODR |= (1<<13);}
#define LED_TOGGLE() 	{GPIOC->ODR ^= (1<<13);}

u16 adc = 0;

extern void loop(void){
	LED_TOGGLE();
	adc = read_adc();
	printf("adc %d \r\n", adc);
	
	HAL_Delay(500);
}
