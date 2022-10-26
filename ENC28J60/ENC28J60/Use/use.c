
#include "use.h"
#include "enc28j60.h"

extern void setup(void){
	enc28j60_init();
}

extern void loop(void){
	enc28j60_poll();
}
