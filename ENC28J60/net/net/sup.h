
#ifndef SUP_H
#define SUP_H
#include "main.h"
extern uint8_t copy_arr(uint8_t* dest, uint8_t* source, uint8_t len);
extern bool com_arr(uint8_t* a,const uint8_t* b, uint8_t len);
extern uint16_t swap16(uint16_t data);

extern u16 icmp_checksum(u08 *data, u16 len);
extern u16 icmp_ip_checksum(u08 *ip_data, u16 len);
extern u32 crc32(u08 *buf, u08 size);

#endif
