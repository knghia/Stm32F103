
#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void adc_dma(void){
	/************ ADC DMA ************
	1. Enable clock GPIOA : ADC 1 PA6 ~ analog mode
	2. Enable clock adc 1
	3. Data Alignment RIGHT
	4. sample time : 13.5
	5. External trigger conversion mode for regular channels
	6. External event select for regular group
	7. DMA request
	8. Length convert = 1
	9. Continuous conversion : singel mode
	10. Set index
	11. ADC Convert on 
	****************************************/
	
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
	// 7. DMA request
	ADC1->CR2 |= (1<<8);
  // 8. Length convert = 1
	ADC1->SQR1 &=~(B1111<<20);
	ADC1->SQR1 |= (0<<20);
	// 9. Continuous conversion : Continuous
	ADC1->CR2 |= (1<<1);
	// 10. set index
	ADC1->SQR3 |= (6<<0);
	// 11. ADC Convert on 
	ADC1->CR2 |= (1<<0);

	ADC1->DR = 0;
	ADC1->CR2 |= (1<<22);
}

void dma1_config(uint32_t srcAdd,uint32_t destAdd,uint32_t lenght){
	
	/************ DMA 1 INIT ************
	0. Enable clock
	1. Read from peripheral
	2. Priority level: HIGH
	3. Circular mode
	4. Memory and peripheral data size
	5. Enable interrupt
	****************************************/
	/* 0. Enable clock */
	RCC->AHBENR |= (1<<0);
	/* 1. Read from peripheral */
	DMA1_Channel1->CCR &=~ (1<<4);
	/* 2. Priority level: HIGH */
	DMA1_Channel1->CCR &=~ (3<<12);
	DMA1_Channel1->CCR |= (1<<12);
	/* 3. Circular mode */
	DMA1_Channel1->CCR |= (1<<5);
	/* 4. Memory and peripheral data size : 16bit */
	DMA1_Channel1->CCR &=~ (3<<8)|(3<<10);
	DMA1_Channel1->CCR |= (1<<8)|(1<<10);
	/* 5. Enable interrupt */
	DMA1_Channel1->CCR |= (1<<3)|(1<<2)|(1<<1);
	
	// NVIC DMA1 Channel 1: 11
	/* 
		Polarity
		11/4 = 2
		(11-2*4)= 3-> (3)*4 = 12
	*/
	NVIC->IP[2] = (0<<12);
	/*
		Enable
		11/32 = 0
		11-32*0= 11
	*/
	NVIC->ISER[0] = (1<<11);
	
	/************** DMA 1 SET ADDRESS *****************
	1. Peripheral Address
	2. Memory Address
	3. Length of DMA
	************************************************/
	/* 1. Peripheral Address */
	DMA1_Channel1->CPAR = srcAdd;
	/* 2. Memory Address */
	DMA1_Channel1->CMAR = destAdd;
	/* 3. Length of DMA */
	DMA1_Channel1->CNDTR = lenght;
	
	
	/* Enable the DMA */
	DMA1_Channel1->CCR |= (1<<0);
}

#define LED_ON() 	{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define LED_TOGGLE() {GPIOC->ODR ^= (1<<13);}

uint16_t adc_value[1];

extern void setup(void){
	gpio_init();
	adc_dma();
	dma1_config((uint32_t)&ADC1->DR, (uint32_t)adc_value, 1);
}

extern void loop(void){
	LED_TOGGLE();
	HAL_Delay(500);
}





