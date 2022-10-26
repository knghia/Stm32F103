
#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void adc_single(void){
	// 1. Enable clock GPIOA : ADC 1 PA6,PA7 ~ analog mode
	RCC->APB2ENR |= (1<<2);
	GPIOA->CRL &=~ 0xFF000000;
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
	HAL_Delay(100);
}

uint16_t read_adc(){
	ADC1->DR = 0;
	ADC1->CR2 |= (1<<22);
	while(ADC1->SR&(1<<1));
	return ADC1->DR;
}

extern void setup(void){
	gpio_init();
	adc_single();
}

#define LED_ON() 	{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define LED_TOGGLE() {GPIOC->ODR ^= (1<<13);}

uint16_t adc_value = 0;

extern void loop(void){
	LED_TOGGLE();
	HAL_Delay(100);
	
	adc_value = read_adc();
}
