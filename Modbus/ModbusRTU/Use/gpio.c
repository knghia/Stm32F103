#include "main.h"
#include "use.h"
#include "mbrtu.h"
#include <stdbool.h>

/*
 * MODBUS
 */
#define REG_INPUT_NREGS 6
#define REG_INPUT_START 1000
uint16_t usRegInputBuf[REG_INPUT_NREGS] = {0};

#define REG_HOLDING_NREGS 6
#define REG_HOLDING_START 2000
uint16_t usRegHoldingBuf[REG_HOLDING_NREGS] = {7,100,255,255};

#define REG_COIL_NREGS 6
#define REG_COIL_START 0
uint16_t usRegCoilBuf[REG_COIL_NREGS] = {0};

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

extern MBRTU_Error mbrtu_force_coil_cb(uint8_t* data_frame, uint16_t begin_add, uint16_t len){
	if((begin_add >= REG_INPUT_START)
        && ((begin_add + len)<=(REG_INPUT_NREGS+REG_INPUT_START))){
		if
		uint16_t i = begin_add-REG_INPUT_START;
        while(len>0){
            *data_frame++ = (uint8_t)(usRegCoilBuf[i]>>8);
            *data_frame++ = (uint8_t)(usRegCoilBuf[i]%256);
            i++;
            len--;
        }
		return MB_NONE;
	}
	return MB_ADD_ERROR;
}

extern MBRTU_Error mbrtu_input_register_cb(uint8_t* data_frame, uint16_t begin_add, uint16_t len){
	if((begin_add >= REG_INPUT_START)
        && ((begin_add + len)<=(REG_INPUT_NREGS+REG_INPUT_START))){

		uint16_t i = begin_add-REG_INPUT_START;
        while(len>0){
            *data_frame++ = (uint8_t)(usRegInputBuf[i]>>8);
            *data_frame++ = (uint8_t)(usRegInputBuf[i]%256);
            i++;
            len--;
        }
		return MB_NONE;
	}
	return MB_ADD_ERROR;
}

extern MBRTU_Error mbrtu_holding_register_cb(uint8_t* data_frame, uint16_t begin_add, uint16_t len){
	if((begin_add >= REG_HOLDING_START)
        && ((begin_add + len)<=(REG_HOLDING_START + REG_HOLDING_NREGS)))
	{
		uint16_t i = begin_add-REG_HOLDING_START;
        while(len>0){
            usRegHoldingBuf[i] = (uint16_t)(*data_frame++ << 8);
            usRegHoldingBuf[i] += (uint16_t)(*data_frame++);
            i++;
            len--;
        }
		return MB_NONE;
	}
	return MB_ADD_ERROR;
}

