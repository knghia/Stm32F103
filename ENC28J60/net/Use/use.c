#include <stdio.h>
#include "use.h"

u08 mymac[6] = {0x08,0x10,0x19,0x97,0x25,0x25};
u08 myip[4] =  {192,168,137,100};       
u16 myport = 5004;

extern void setup(void){
	net_init(mymac, myip, myport);
}

extern void loop(void){
		net_analysis();
		delay_ms(10);
}
