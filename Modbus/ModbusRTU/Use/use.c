#include "main.h"
#include "use.h"
#include "mbrtu.h"
#include <stdbool.h>

/*
 * MODBUS
 */
#define REG_INPUT_NREGS 6
#define REG_INPUT_START 1000
u16 usRegInputBuf[REG_INPUT_NREGS] = {0};

#define REG_HOLDING_NREGS 6
#define REG_HOLDING_START 2000
u16 usRegHoldingBuf[REG_HOLDING_NREGS] = {7,100,255,255};

#define REG_COIL_NREGS 6
#define REG_COIL_START 2000
u16 usRegCoilBuf[REG_COIL_NREGS] = {0};


extern void setup(void){
	mbrtu_init();
}

extern void loop(void){
	mbrtu_poll();
	usRegInputBuf[0] = usRegHoldingBuf[0];
	usRegInputBuf[1] = usRegHoldingBuf[1];
	usRegInputBuf[2] = usRegHoldingBuf[1];
	usRegInputBuf[3] = usRegHoldingBuf[3];
}

MBRTU_Error mbrtu_force_coil_cb(u08* data_frame, u16 begin_add, u16 len){
	if((begin_add >= REG_INPUT_START)
        && ((begin_add + len)<=(REG_INPUT_NREGS+REG_INPUT_START))){
		u16 i = begin_add-REG_INPUT_START;
		if (len == 1){
			usRegCoilBuf[i] = (u16)(*data_frame++ << 8);
			usRegCoilBuf[i] += (u16)(*data_frame++);
		}
		return MB_NONE;
	}
	return MB_ADD_ERROR;
}

MBRTU_Error mbrtu_input_register_cb(u08* data_frame, u16 begin_add, u16 len){
	if((begin_add >= REG_INPUT_START)
        && ((begin_add + len)<=(REG_INPUT_NREGS+REG_INPUT_START))){

		u16 i = begin_add-REG_INPUT_START;
        while(len>0){
            *data_frame++ = (u08)(usRegInputBuf[i]>>8);
            *data_frame++ = (u08)(usRegInputBuf[i]%256);
            i++;
            len--;
        }
		return MB_NONE;
	}
	return MB_ADD_ERROR;
}

MBRTU_Error mbrtu_holding_register_cb(u08* data_frame, u16 begin_add, u16 len){
	if((begin_add >= REG_HOLDING_START)
        && ((begin_add + len)<=(REG_HOLDING_START + REG_HOLDING_NREGS)))
	{
		u16 i = begin_add-REG_HOLDING_START;
        while(len>0){
            usRegHoldingBuf[i] = (u16)(*data_frame++ << 8);
            usRegHoldingBuf[i] += (u16)(*data_frame++);
            i++;
            len--;
        }
		return MB_NONE;
	}
	return MB_ADD_ERROR;
}

