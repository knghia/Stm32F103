
#ifndef ILI9341_H
#define ILI9341_H
#include "main.h"
#include <inttypes.h>

typedef void (*_rst_low)(void);
typedef void (*_rst_high)(void);

typedef void (*_csx_low)(void);
typedef void (*_csx_high)(void);

typedef void (*_dcx_high)(void);
typedef void (*_dcx_low)(void);

typedef void (*_rdx_high)(void);
typedef void (*_rdx_low)(void);

typedef void (*_wdx_high)(void);
typedef void (*_wdx_low)(void);



typedef void (*_LCD0_low)(void);
typedef void (*_LCD0_high)(void);

typedef void (*_LCD1_low)(void);
typedef void (*_LCD1_high)(void);

typedef void (*_LCD2_low)(void);
typedef void (*_LCD2_high)(void);

typedef void (*_LCD3_low)(void);
typedef void (*_LCD3_high)(void);

typedef void (*_LCD4_low)(void);
typedef void (*_LCD4_high)(void);

typedef void (*_LCD5_low)(void);
typedef void (*_LCD5_high)(void);

typedef void (*_LCD6_low)(void);
typedef void (*_LCD6_high)(void);

typedef void (*_LCD7_low)(void);
typedef void (*_LCD7_high)(void);

typedef void (*_LCD8_low)(void);
typedef void (*_LCD8_high)(void);

typedef void (*_LCD9_low)(void);
typedef void (*_LCD9_high)(void);

typedef void (*_LCD10_low)(void);
typedef void (*_LCD10_high)(void);

typedef void (*_LCD11_low)(void);
typedef void (*_LCD11_high)(void);

typedef void (*_LCD12_low)(void);
typedef void (*_LCD12_high)(void);

typedef void (*_LCD13_low)(void);
typedef void (*_LCD13_high)(void);

typedef void (*_LCD14_low)(void);
typedef void (*_LCD14_high)(void);

typedef void (*_LCD15_low)(void);
typedef void (*_LCD15_high)(void);

typedef enum{
	NOP = 																		0,
	SOFTWARE_RESET = 													0x01h,
	READ_DISPLAY_IDENTIFICATION_INFORMATION = 0x04h,
	READ_DISPLAY_STATUS = 										0x09h,
	READ_DISPLAY_POWER_MODE = 								0x0Ah,
	READ_DISPLAY_MADCTL = 										0x0Bh,
	READ_DISPLAY_PIXEL_FORMAT = 							0x0Ch,
	READ_DISPLAY_IMAGE_FORMAT = 							0x0Dh,
	READ_DISPLAY_SIGNAL_MODE = 								0x0Eh,
	READ_DISPLAY_SELF_DIAGNOSTIC_RESULT = 		0x0Fh,
	READ_SLEEP_MODE = 												0x10h,
	READ_SLEEP_OUT = 													0x11h,
	
	PARTIAL_MODE_ON = 												0x12h,
	NORMAL_DISPLAY_MODE_ON = 									0x13h,
	DISPLAY_INVERSION_OFF = 									0x20h,
	DISPLAY_INVERSION_ON = 										0x21h,
	GAMMA_SET = 															0x26h,
	DISPLAY_OFF = 														0x28h,
	DISPLAY_ON = 															0x29h,
	
	COLUMN_ADDRESS_SET = 											0x2A
}ILI9341_COMMAND;

extern void ILI9341_add_func(ILI9341_COMMAND command);
extern void ILI9341_write_command(ILI9341_COMMAND command);
extern void ILI9341_write_data(uint16_t data);
extern uint16_t ILI9341_read_data(uint16_t data);



#endif
