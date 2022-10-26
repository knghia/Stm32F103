#include "ILI9341.h"

_csx_low CSX_LOW;
_csx_high CSX_HIGH;

_rst_low RST_LOW;
_rst_high RST_HIGH;

_dcx_high DCX_HIGH;
_dcx_low DCX_LOW;

_rdx_high RDX_HIGH;
_rdx_low RDX_LOW;

_wdx_high WCX_HIGH;
_wdx_low WCX_LOW;

_LCD0_low 	LCD0_LOW;
_LCD0_high 	LCD0_HIGH;

_LCD1_low 	LCD1_LOW;
_LCD1_high 	LCD1_HIGH;

_LCD2_low 	LCD2_LOW;
_LCD2_high 	LCD2_HIGH;

_LCD3_low 	LCD3_LOW;
_LCD3_high 	LCD3_HIGH;

_LCD4_low 	LCD4_LOW;
_LCD4_high 	LCD4_HIGH;

_LCD5_low 	LCD5_LOW;
_LCD5_high 	LCD5_HIGH;

_LCD6_low 	LCD6_LOW;
_LCD6_high 	LCD6_HIGH;

_LCD7_low 	LCD7_LOW;
_LCD7_high 	LCD7_HIGH;

_LCD8_low 	LCD8_LOW;
_LCD8_high 	LCD8_HIGH;

_LCD9_low 	LCD9_LOW;
_LCD9_high 	LCD9_HIGH;

_LCD10_low 	LCD10_LOW;
_LCD10_high LCD10_HIGH;

_LCD11_low 	LCD11_LOW;
_LCD11_high LCD11_HIGH;

_LCD12_low 	LCD12_LOW;
_LCD12_high LCD12_HIGH;

_LCD13_low 	LCD13_LOW;
_LCD13_high LCD13_HIGH;

_LCD14_low 	LCD14_LOW;
_LCD14_high LCD14_HIGH;

_LCD15_low 	LCD15_LOW;
_LCD15_high LCD15_HIGH;

extern void ILI9341_add_func(ILI9341_COMMAND command){
}

void ILI9341_setup_data(uint16_t data){
	uint16_t i = 0;
	i = (data>>0)&0x01;	if(i == 0){LCD0_LOW();}else{LCD0_HIGH();}
	i = (data>>1)&0x01;	if(i == 0){LCD1_LOW();}else{LCD1_HIGH();}
	i = (data>>2)&0x01;	if(i == 0){LCD2_LOW();}else{LCD2_HIGH();}
	i = (data>>3)&0x01;	if(i == 0){LCD3_LOW();}else{LCD3_HIGH();}
	i = (data>>4)&0x01;	if(i == 0){LCD4_LOW();}else{LCD4_HIGH();}
	i = (data>>5)&0x01;	if(i == 0){LCD5_LOW();}else{LCD5_HIGH();}
	i = (data>>6)&0x01;	if(i == 0){LCD6_LOW();}else{LCD6_HIGH();}
	i = (data>>7)&0x01;	if(i == 0){LCD7_LOW();}else{LCD7_HIGH();}
	i = (data>>8)&0x01;	if(i == 0){LCD8_LOW();}else{LCD8_HIGH();}
	i = (data>>9)&0x01;	if(i == 0){LCD9_LOW();}else{LCD9_HIGH();}
	i = (data>>10)&0x01;if(i == 0){LCD10_LOW();}else{LCD10_HIGH();}
	i = (data>>11)&0x01;if(i == 0){LCD11_LOW();}else{LCD11_HIGH();}
	i = (data>>12)&0x01;if(i == 0){LCD12_LOW();}else{LCD12_HIGH();}
	i = (data>>13)&0x01;if(i == 0){LCD13_LOW();}else{LCD13_HIGH();}
	i = (data>>14)&0x01;if(i == 0){LCD14_LOW();}else{LCD14_HIGH();}
	i = (data>>15)&0x01;if(i == 0){LCD15_LOW();}else{LCD15_HIGH();}
}

extern void ILI9341_write_command(ILI9341_COMMAND command){
	RST_HIGH();
	CSX_LOW();
	DCX_LOW();
	RDX_HIGH();
	
	WCX_HIGH();
	ILI9341_setup_data(command);
	WCX_LOW();
	CSX_HIGH();
}

extern void ILI9341_write_data(uint16_t data){
	RST_HIGH();
	CSX_LOW();
	DCX_HIGH();
	RDX_HIGH();
	
	WCX_HIGH();
	ILI9341_setup_data(command);
	WCX_LOW();
	CSX_HIGH();
}

extern uint16_t ILI9341_read_data(uint16_t data){
	RST_HIGH();
	CSX_LOW();
	DCX_HIGH();
	WCX_HIGH();
	
	RDX_HIGH();
	ILI9341_setup_data(command);
	WCX_LOW();
	CSX_HIGH();
}
