
#ifndef ICMP_H
#define ICMP_H

#include <inttypes.h>
#include <stdbool.h>
#include "main.h"

#define IPV4_ETHERNET_TYPE 				0x0800
#define IPV4_HEADER_LENGTH				0x45
#define IPV4_SERVICES							0x00
#define IPV4_IDENTIFICATION				0x0810
#define IPV4_FLAG									0x0000
#define IPV4_TIME_TO_LIVE					128
#define IPV4_PROTOCOL_ICMP				0x01

#define ICMP_REPLY								0x00
#define ICMP_REQUEST							0x08
#define ICMP_CODE									0x00
#define ICMP_IDENTIFIER						0x0001
#define ICMP_SEQUENCE_NUMBER			0x0015


#define IPV4_I_MAC_SOURCE					0
#define IPV4_I_MAC_DEST						6
#define IPV4_I_ETHERNET_TYPE			12

#define I_IPV4_HARD_LENGTH			14
#define I_IPV4_SERVICES					15
#define I_IPV4_TOTAL_LENGTH			16
#define I_IPV4_IDENTIFICATION		18
#define I_IPV4_FLAG							20
#define I_IPV4_TIMETOLIVE				22
#define I_IPV4_PROTOCOL					23
#define I_IPV4_CHECKSUM					24
#define I_IPV4_SOURCE_IP				26
#define I_IPV4_DEST_IP					30

#define I_ICMP_TYPE								34
#define I_ICMP_CODE								35
#define I_ICMP_CHECKSUM						36
#define I_ICMP_IDENTIFIER					38
#define I_ICMP_SEQUENCE_NUMBER		40

#define IPV4_ICMP_SIZE						42
#define IPV4_SIZE									28
#define ICMP_SIZE									8

#define DEBUG_ICMP

typedef struct{
	/* It is Ethernet Frame II */
	uint8_t MAC_source[6];
	uint8_t MAC_dest[6];
	uint16_t Ethernet_type;
	/* IP */
	uint8_t  Header_length; 
	uint8_t  Services;
	/* Total length : Header_length - data[] or all - 14 */
	uint16_t TotalLength;
	uint16_t Identification;
	uint16_t Flag;
	uint8_t  TimeToLive;
	uint8_t  Protocol;
	uint16_t CheckSum;
	uint8_t  SourceIP[4];
	uint8_t  DestIP[4];

	/* ICMP */
	uint8_t ICMP_Type;
	uint8_t ICMP_Code;
	uint16_t ICMP_Checksum; 
	uint16_t ICMP_Identification;
	uint16_t ICMP_SequenceNumber;
	uint8_t ICMP_data[255]; 
}ICMP_Struct;

extern void icmp_send_package(uint8_t mac_dest[6],const uint8_t ip_dest[4], uint8_t* data, uint16_t length);
extern bool icmp_receive_package(void);

#endif
