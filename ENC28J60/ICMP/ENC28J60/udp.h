
#ifndef UDP_H
#define UDP_H

#include <inttypes.h>
#include <stdbool.h>
#include "main.h"

#define UDP_ETHERNET_TYPE 			0x0800
#define UDP_HEADER_LENGTH				0x45
#define UDP_SERVICES						0x00
#define UDP_FLAG								0x0000
#define UDP_TIME_TO_LIVE				128
#define UDP_PROTOCOL						0x11
#define UDP_IP_IDENTIFICATION   0x8BFE

#define UDP_I_MAC_SOURCE				0
#define UDP_I_MAC_DEST					6
#define UDP_I_ETHERNET_TYPE			12

#define UDP_IP_I_HARD_LENGTH			14
#define UDP_IP_I_SERVICES					15
#define UDP_IP_I_TOTAL_LENGTH			16
#define UDP_IP_I_IDENTIFICATION		18
#define UDP_IP_I_FLAG							20
#define UDP_IP_I_TIMETOLIVE				22
#define UDP_IP_I_PROTOCOL					23
#define UDP_IP_I_CHECKSUM					24
#define UDP_IP_I_SOURCE_IP				26
#define UDP_IP_I_TARGET_IP				30

#define UDP_I_SOURCE_PORT				34
#define UDP_I_DEST_PORT					36
#define UDP_I_LENGTH						38
#define UDP_I_CHECKSUM					40
#define UDP_I_DATA							42

#define ETHERNET_II_SIZE 				14
#define UDP_IP_SIZE 						28
#define UDP_SIZE 								8
#define UDP_FRAME_SIZE 					42

#define DEBUG_UDP

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

	/* UDP */
	uint16_t UDP_Source_Port;
	uint16_t UDP_Dest_Port;
	uint16_t UDP_Length; 
	uint16_t UDP_Checksum;
	uint8_t UDP_data[255]; 
}UDP_Struct;

typedef struct{
	uint8_t MAC_dest[6];
	uint8_t DestIP[4];
}Dest_Struct;

#define SOURCE_PORT 5004

extern void udp_send_package(uint8_t mac_dest[6],const uint8_t ip_dest[4],uint16_t dest_port, uint8_t* data, uint16_t length);
extern bool udp_receive_package(void);

#endif
