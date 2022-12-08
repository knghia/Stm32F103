#include <stdio.h>
#include "use.h"

extern void setup(void){
	int ret;
	ret = W5500_Init();
	if (ret != 0) {
		printf("w5500 init fail, ret is %d\r\n", ret);
	} else {
		printf("w5500 init success\r\n");
	}
}

extern void loop(void){
	delay_ms(100);
}
