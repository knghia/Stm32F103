<span style="font-family:Courier New">

# Flash led by update tim2

```c
void tim_2_init(void){
	// 0. Enable cleck tim 2 
	RCC->APB1ENR |= (1<<0);
	TIM2->CNT = 0;
	TIM2->PSC = 360-1;
	TIM2->ARR = 50000-1;
	// 1. Enable UDIS tim 2
	TIM2->CR1 &=~	(1<<1);
	// 2. Update interrupt enable
	TIM2->DIER |= (1<<0);
	// Enable time 1
	TIM2->CR1 |= (1<<0);
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
}

void TIM2_IRQHandler(void)
{
	if (TIM2->SR & (1<<0))
	{
		LED_TOGGLE();
	}
	TIM2->SR &=~ (1<<0);
}
```
</span>