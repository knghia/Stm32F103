
#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void adc1_single_cvt_scan_dma(u32 srcAdd, u32 destAdd, u32 lenght){
	/* 1. Enable clock GPIOA */
	/* ADC 1 PA6,PA7 ~ analog mode */
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
	
	/* 7. Continuous conversion mode */
	ADC1->CR2 |= (1<<1);
	/* 8. Scan mode */
	ADC1->CR1 |= (1<<8);
	/* 8. DMA */
	ADC1->CR2 |= (1<<8);
	
	/* 9. Conversion : 2 */
	ADC1->SQR1 |= (1<<20);
	/* 10. ADC set index */
	ADC1->SQR3 = (6<<0)|(7<<5);
	
	/************ DMA 1 INIT ************
	0. Enable clock
	1. Read from peripheral
	2. Priority level: HIGH
	3. Circular mode
	4. Memory and peripheral data size
	5. Memory increment mode
	****************************************/
	/* 0. Enable clock */
	RCC->AHBENR |= (1<<0);
	/* 1. Read from peripheral */
	DMA1_Channel1->CCR &=~ (1<<4);
	/* 2. Priority level: LOW */
	DMA1_Channel1->CCR &=~ (3<<12);
	/* 3. Circular mode  */
	DMA1_Channel1->CCR |= (1<<5);
	/* 4. Memory and peripheral data size : 16bit */
	DMA1_Channel1->CCR |= (1<<8)|(1<<10);
	/* 5. Memory increment mode */
	DMA1_Channel1->CCR |= (1<<7);

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
	
	/* ADC Convert on */
	ADC1->CR2 |= (1<<0);
	/* Enable the DMA */
	DMA1_Channel1->CCR |= (1<<0);
	/* ADC Start Conversion */
	ADC1->CR2 |= (1<<22);
}

u16 adc[2] = {0};

extern void setup(void){
	gpio_init();
	adc1_single_cvt_scan_dma((u32)&ADC1->DR, (u32)adc, 2);
}

extern void loop(void){
	HAL_Delay(500);
	printf("adc %d %d \r\n", adc[0], adc[1]);
}



