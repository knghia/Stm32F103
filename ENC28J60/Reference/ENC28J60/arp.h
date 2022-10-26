#ifndef ARP_H_
#define ARP_H_
//--------------------------------------------------
//Include cac thu vien can thiet
#include "main.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "net.h"
//-------------------------------------------------
//dinh nghia thoi gian xoa bang arp
#define MAX_TIME_SAVE 10 //(phut)
//-------------------------------------------------
#define COUNT_TICK (MAX_TIME_SAVE*60000)
//-------------------------------------------------
void ARP_read_packet(uint8_t *ARP_Buff,uint16_t len);
void ARP_send_request(uint8_t *ip_dest);
int8_t ARP_table_checkIP(uint8_t *ip_check);
void ARP_table_setIP(uint8_t *ip_set, uint8_t *mac_set);
void ARP_clear_table(void);
void ARP_table_get_MAC(uint8_t *ip_check,uint8_t * MAC_dest);
//--------------------------------------------------
#endif /* ARP_H_ */
