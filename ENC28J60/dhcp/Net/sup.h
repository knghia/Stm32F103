
#ifndef SUP_H
#define SUP_H
#include "main.h"

extern u08 copy_arr(u08* dest, u08* source, u16 len);
extern bool com_arr(u08* a,const u08* b, u16 len);
extern u16 swap16(uint16_t data);
extern u32 swap32(u32 data);

extern u32 crc32(u08 *buf, u08 size);

extern u16 icmp_checksum(u08 *data, u16 len);
extern u16 ipv4_checksum(u08 *data, u16 len);
extern u16 udp_checksum(u08 *data, u16 len);
extern u16 tcp_checksum(u08 *data, u16 len);

#endif
