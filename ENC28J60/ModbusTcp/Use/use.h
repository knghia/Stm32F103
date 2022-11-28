
#ifndef USE_H
#define USE_H
#include "main.h"

extern void setup(void);
extern void loop(void);
extern void net_udp_handle(u08 num);
extern void net_tcp_ip_handle(u08 num);

extern MBTCP_Error net_mb_tcp_input_register_cb(uint8_t* data_frame, uint16_t begin_add, uint16_t len);
extern MBTCP_Error net_mb_tcp_holding_register_cb(uint8_t* data_frame, uint16_t begin_add, uint16_t len);

#endif
