
#ifndef SUPPORT_H
#define SUPPORT_H
#include <inttypes.h>
#include <inttypes.h>
#include <stdbool.h>

extern uint8_t copy_arr(uint8_t* dest, uint8_t* source, uint8_t len);
extern bool com_arr(uint8_t* a,const uint8_t* b, uint8_t len);
extern uint16_t swap16(uint16_t data);

#endif
