#ifndef NET_H
#define NET_H

#include "main.h"

#define DEBUG

// ******* ETH *******
#define ETH_HEADER_LEN					14
// values of certain bytes:
#define ETHTYPE_ARP_H_V 				0x08
#define ETHTYPE_ARP_L_V 				0x06
#define ETHTYPE_IP_H_V  				0x08
#define ETHTYPE_IP_L_V  				0x00
// byte positions in the ethernet frame:
//
// Ethernet type field (2bytes):
#define ETH_TYPE_H_P 						12
#define ETH_TYPE_L_P 						13
//
#define ETH_DST_MAC 						0
#define ETH_SRC_MAC 						6


// ******* ARP *******
#define ETH_ARP_OPCODE_REPLY_H_V 	0x0
#define ETH_ARP_OPCODE_REPLY_L_V 	0x02
//
#define ETHTYPE_ARP_L_V 				0x06
// arp.dst.ip
#define ETH_ARP_DST_IP_P 				0x26
// arp.opcode
#define ETH_ARP_OPCODE_H_P 			0x14
#define ETH_ARP_OPCODE_L_P 			0x15
// arp.src.mac
#define ETH_ARP_SRC_MAC_P 			0x16
#define ETH_ARP_SRC_IP_P 				0x1c
#define ETH_ARP_DST_MAC_P 			0x20
#define ETH_ARP_DST_IP_P				0x26

// ******* IP *******
#define IP_HEADER_LEN						20
// ip.src
#define IP_SRC_P 								0x1a  //26
#define IP_DST_P 								0x1e  //30
#define IP_HEADER_LEN_VER_P 		0xe
#define IP_CHECKSUM_P 					0x18 //24
#define IP_TTL_P 								0x16   //22
#define IP_FLAGS_P 							0x14  //20
#define IP_P 										0xe		//14
#define IP_TOTLEN_H_P 					0x10  //16
#define IP_TOTLEN_L_P 					0x11  //17

#define IP_PROTO_P 							0x17  

#define IP_PROTO_ICMP_V 				1
#define IP_PROTO_TCP_V 					6
// 17=0x11
#define IP_PROTO_UDP_V 					17
// ******* ICMP *******
#define ICMP_TYPE_ECHOREPLY_V		0
#define ICMP_TYPE_ECHOREQUEST_V	8
//
#define ICMP_TYPE_P 						0x22
#define ICMP_CHECKSUM_P 				0x24

// ******* UDP *******
#define UDP_HEADER_LEN				8
//
#define UDP_SRC_PORT_H_P 			0x22
#define UDP_SRC_PORT_L_P 			0x23
#define UDP_DST_PORT_H_P 			0x24
#define UDP_DST_PORT_L_P 			0x25
//
#define UDP_LEN_H_P 					0x26
#define UDP_LEN_L_P 					0x27
#define UDP_CHECKSUM_H_P 			0x28
#define UDP_CHECKSUM_L_P 			0x29
#define UDP_DATA_P 						0x2a

// ******* TCP *******
#define TCP_SRC_PORT_H_P 			0x22
#define TCP_SRC_PORT_L_P 			0x23
#define TCP_DST_PORT_H_P 			0x24
#define TCP_DST_PORT_L_P 			0x25
// the tcp seq number is 4 bytes 0x26-0x29
#define TCP_SEQ_H_P 					0x26
#define TCP_SEQACK_H_P 				0x2a
// flags: SYN=2
#define TCP_FLAGS_P 					0x2f
#define TCP_FLAGS_SYN_V 			2
#define TCP_FLAGS_FIN_V 			1
#define TCP_FLAGS_PUSH_V 			8
#define TCP_FLAGS_SYNACK_V 		0x12
#define TCP_FLAGS_ACK_V 			0x10
#define TCP_FLAGS_PSHACK_V 		0x18
//  plain len without the options:
#define TCP_HEADER_LEN_PLAIN 	20
#define TCP_HEADER_LEN_P 			0x2e
#define TCP_CHECKSUM_H_P 			0x32
#define TCP_CHECKSUM_L_P 			0x33
#define TCP_OPTIONS_P 				0x36

extern bool net_analysis(void);
extern void net_init(u08 mymac[6], u08 myip[4], u08 myport);

#define ARP_PACKET_LEN					42
#define ARP_ETHERNET_TYPE				0x0806
#define ARP_HARDWAVE_TYPE				0x0001
#define ARP_PROTOCOL_TYPE				0x0800
#define ARP_SIZE								0x0604
#define ARP_OPCODE_REPLY				0x0002
#define ARP_OPCODE_REQUEST			0x0001
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
}ARP_Frame;

extern bool net_arp_check_broadcast(u08* data, u08 len);
extern void net_arp_reply(u08* ping, u08 len);
extern bool net_arp_get_mac_ip_pc(u08 mac_target[6], u08 ip_target[4], u16 timeout);

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
}ICMP_Frame;

extern void net_icmp_reply(u08* ping, u08 len);
extern bool net_icmp_check(u08* data, u08 len);
extern void net_icmp_response(u08* data, u08 len);

#endif
