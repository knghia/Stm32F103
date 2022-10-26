
#include "use.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void encoder_init(void){
	/* 
		Config PB1, PB12 input pullup
	*/

	RCC->APB2ENR |= (1<<3);

	GPIOB->CRH &=~ 0x000F0000;
	GPIOB->CRH |=  0x00080000;
	
	GPIOB->CRL &=~ 0x000000F0;
	GPIOB->CRL |=  0x00000080;
	
	/* 
		Config PB1,PB12 external interrupt
	*/
	RCC->APB2ENR |= (1<<0);
  // Configure EXTI1 line for PB1
	AFIO->EXTICR[0] |= (1<<4);
	// Configure EXTI1 line for PB12
	AFIO->EXTICR[3] |= (1<<0);

	// Disable the Mask on EXTI 1
	EXTI->IMR |= (1<<1);
	// Disable the Mask on EXTI 12
	EXTI->IMR |= (1<<12);
	
	// Disable Rising Edge for PB1,PB12
	EXTI->RTSR |= (1<<1)|(1<<12);
	// Enable Falling Edge for PB1,PB12
	EXTI->FTSR |= (1<<1)|(1<<12);
	/* 
		NVIC EXTI Line 1, 12 interrupt : 7, 40
		7/4 = 1
		(7-4*1)= 3 -> (3)*8 = 24
		
		40/4 = 10
		(40-4*10)= 0 -> (0)*8 = 0
	*/
	NVIC->IP[1] = (0<<24);
	NVIC->IP[10] = (0<<0);
	/* 
		NVIC EXTI Line 1, 12 interrupt enable
		7/32 = 0
		7-31*0= 7
		
		40/32 = 1
		40-32*1= 8
	*/
	NVIC->ISER[0] = (1<<7);
	NVIC->ISER[1] = (1<<8);
}

extern void setup(void){
	gpio_init();
	encoder_init();
}

#define LED_ON() 	{GPIOC->ODR &=~ (1<<13);}
#define LED_OFF() {GPIOC->ODR |= (1<<13);}
#define READ_PIN(GPIO_PORT,GPIO_PIN) (((GPIO_PORT->IDR & (1<<GPIO_PIN)) == 0x00) ? 0:1)
int32_t count = 0;

void EXTI1_IRQHandler(void)
{
	if (EXTI->PR & (1<<1))
	{
		if ((GPIOB->IDR & (1<<11)) != 0){
			count += 1; 
		}
		else{
			count -= 1; 
		}
		EXTI->PR |= (1<<1);
	}
}

void EXTI15_10_IRQHandler(void){
	if (EXTI->PR & (1<<12))
	{
		if ((GPIOB->IDR & (1<<1)) == 0){
			count += 1; 
		}
		else{
			count -= 1; 
		}
		EXTI->PR |= (1<<12);
	}
}

extern void loop(void){
	LED_ON();
	HAL_Delay(500);
	LED_OFF();
	HAL_Delay(500);
}
