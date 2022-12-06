#ifndef USE_H
#define USE_H

#include "main.h"
#include "mbrtu.h"

extern void setup(void);
extern void loop(void);

extern MBRTU_Error mbrtu_input_register_cb(uint8_t* data_frame, uint16_t begin_add, uint16_t len);
extern MBRTU_Error mbrtu_holding_register_cb(uint8_t* data_frame, uint16_t begin_add, uint16_t len);

#endif
