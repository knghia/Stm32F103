#include "use.h"
#include "binary.h"

void gpio_init(void){
	// Enable clock GPIOC 
	RCC->APB2ENR |= (1<<4);
	GPIOC->CRH &=~ 0x00F00000;
	GPIOC->CRH |= 0x00100000;
}

void tim_1_init(void){
	/* 0. Enable cleck tim 1  */
	RCC->APB2ENR |= (1<<11);
	/* 1. Setup */
	TIM1->CNT = 0;
	TIM1->PSC = 72-1;
	TIM1->ARR = 500-1;
	/* 2. Repetation */
	TIM1->RCR = 0;
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
	
	/* TIM2 Normal setup */
	RCC->APB1ENR |= (1<<0);
	TIM2->CNT = 0;
	TIM2->PSC = 72-1;
	TIM2->ARR = 0xFFFF;
	
	/* TIM2 Input capture mode : Page314 */
	
	/* 1. Select the active input:  CC1 channel is configured as input, IC1 is mapped on TI1 */
	TIM2->CCMR1 |= (B01<<0);
	/* 2. Program the needed input filter: 0011: fSAMPLING=fCK_INT, N=8 */
	TIM2->CCMR1 |= (B0011<<4);
	/* 3. Select the edge: falling edge */
	TIM2->CCER |= (1<<1);
	/* 4. Input capture 1 prescaler: no prescaler */
	TIM2->CCMR1 &=~ (B11<<2);
	/* 5. Enable capture from the counter */
	TIM2->CCER |= (1<<0);
	/* 6. Enable the related interrupt request :
	CC1IE bit in the TIMx_DIER register 
	*/
	TIM2->DIER |= (1<<1);
	/* 
		NVIC TIM 2 update : 28
		28/4 = 7
		(28-4*7)= 0-> (0)*8 = 0
	*/
	NVIC->IP[7] = (0<<0);
	/* 
		NVIC TIM 2 update : enable
		28/31 = 0
		28-31*0= 28
	*/
	NVIC->ISER[0] = (1<<28);
	
	/* 7. Enable capture from the counter */
	TIM2->CR1 |= (1<<0);
}
typedef enum{
	IDLE = 0,
	START = 1,
}CAPTURE_STATE;

CAPTURE_STATE state = START;
uint16_t pre_value = 0;
uint16_t value = 0;
int frequency = 0;
int count = 0;

void TIM2_IRQHandler(void)
{
	/* input cature 1: CC1F = 1 */
	if (TIM2->SR & (1<<1))
	{
		switch (state){
			case IDLE:{
				pre_value = TIM2->CCR1;
				state = START;
				break;
			}
			case START:{
				value = TIM2->CCR1;
				if (value > pre_value){
					frequency = value - pre_value;
				}
				else{
					frequency = 0xFFFF - pre_value+ value;
				}
				state = IDLE;
				break;
			}
		}
		TIM2->CCR1 = 0;
		TIM2->SR &=~ (1<<1);
		count+=1;
	}
}

extern void setup(void){
	gpio_init();
	tim_1_init();
	tim_2_init();
}


extern void loop(void){
}



