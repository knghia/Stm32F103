#include <stdio.h>
#include "use.h"

extern void setup(void){
	W5500_Init();
}

extern void loop(void){
	delay_ms(100);
}
