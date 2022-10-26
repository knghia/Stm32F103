#ifndef NET_H_
#define NET_H_
//--------------------------------------------------
//Include cac thu vien can thiet
#include "main.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "enc28j60.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
//-------------------------------------------------
#define swap16(a) ((((a)>>8)&0xff)|(((a)<<8)&0xff00))
#define swap32(a) ((((a)>>24)&0xff)|(((a)>>8)&0xff00)|(((a)<<8)&0xff0000)|(((a)<<24)&0xff000000))
//-------------------------------------------------
#define BUFFER_LENGTH 512
//-------------------------------------------------
void NET_loop(void);
void NET_read(uint8_t *net_buffer,uint16_t len);
void NET_SendFrame(uint8_t *EthFrame,uint16_t len);
void NET_ipRead(uint8_t *IP_Frame,uint16_t len);
uint16_t NET_ipchecksum(uint8_t *IP_packet_start);
//--------------------------------------------------
#endif /* NET_H_ */
