
#ifndef ARP_H
#define ARP_H
#include "main.h"
#include <inttypes.h>
#include <stdbool.h>

#define DEBUG_ARP

#define ARP_PACKET_LEN					42

#define ARP_ETHERNET_TYPE				0x0806
#define ARP_HARDWAVE_TYPE				0x0001
#define ARP_PROTOCOL_TYPE				0x0800
#define ARP_SIZE								0x0604
#define ARP_OPCODE_REPLY				0x0001
#define ARP_OPCODE_REQUEST			0x0002

/* Index */

#define ARP_I_MAC_DEST					0
#define ARP_I_MAC_SOURCE				6
#define ARP_I_ETHERNET_TYPE			12
#define ARP_I_HARDWAVE_TYPE			14
#define ARP_I_PROTOCOL_TYPE			16
#define ARP_I_SIZE							18
#define ARP_I_OPCODE						20
#define ARP_I_MAC_SENDER				22
#define ARP_I_IP_SENDER					28
#define ARP_I_MAC_TARGET				32
#define ARP_I_IP_TARGET					38

/*
	Destination MAC
	Source MAC
	Ethertype : ARP
	--------------  ARP ------------  

	Hardware Type : HTYPE
			Hard Addr.Length
			Prot.Addr.Type
	Ethernet is 1


	Protocol type (PTYPE)
			Hard Addr.Length
			Prot.Addr.Type
	For IPv4, this has the value 0x0800

	Hardware length (HLEN)
	Protocol length (PLEN)

	Operation
		1 for request
		2 for reply

	Sender hardware address (SHA)
	Sender protocol address (SPA)
	Target hardware address (THA)
	Target protocol address (TPA)
Crc
*/

typedef struct
{
	uint8_t MAC_dest[6];             				// MAC destination
	uint8_t MAC_source[6];                  // MAC source
	uint16_t Ethernet_type;                 // Ethernet type
	uint16_t Hardwave_type;                 // Hardwave type
	uint16_t Protocol_type;                 // Protocol type (ARP)
	uint16_t Size;                          // Size
	uint16_t Opcode;                        // Opcode
	uint8_t MAC_sender[6];                  // Sender MAC
	uint8_t IP_sender[4];                   // Sender IP
	uint8_t MAC_target[6];                  // Target MAC
	uint8_t IP_target[4];                   // Target IP
}ARP_Struct;

extern bool arp_get_mac(uint8_t* mac_target,const uint8_t* ip_target);
extern bool arp_receiver_package(uint8_t* mac);
#endif
