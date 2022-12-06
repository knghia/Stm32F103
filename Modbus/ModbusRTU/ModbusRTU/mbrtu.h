
#ifndef MBRTU_H
#define MBRTU_H

#include <stdbool.h>
#include <inttypes.h>

typedef enum{
	RX_IDLE = 0,
	RX_START = 1,
	RX_COMPLETE = 2,
	TX_IDLE = 3,
	TX_START = 4,
	TX_COMPLETE = 5
}MBRTU_State;

typedef enum{
	MB_NONE = 0,
	MB_ID_ERROR = 1,
	MB_FUNC_ERROR = 2,
	MB_ADD_ERROR = 3,
	MB_CRC_ERROR = 4
}MBRTU_Error;

#define MMBRTU_1_5_T 		750
#define MMBRTU_2_5_T 		1750
#define MBRTU_ID 				68

#define MBRTU_FUNC_04		0x04
#define MBRTU_FUNC_06		0x06
#define MBRTU_FUNC_16		0x10

extern MBRTU_Error mbrtu_poll(void);
extern void mbrtu_init(void);

void mbrtu_tim_init(void);
void mbrtu_tim_start(void);
void mbrtu_tim_stop(void);
extern void mbrtu_tim_call_back(void);

void mbrtu_usart_init(void);

void mbrtu_rx_enable(void);
uint8_t mbrtu_rx_read(void);
extern void mbrtu_rx_call_back(void);

void mbrtu_tx_enable(void);
void mbrtu_tx_data(uint8_t len);
extern void mbrtu_tx_call_back(void);

void mbrtu_response_error(MBRTU_Error e);
void mbrtu_response(uint8_t func, uint16_t add, uint16_t len, uint8_t* data);
void mbrtu_execute(uint8_t* data_frame, uint16_t len);

extern MBRTU_Error mbrtu_input_register_cb(uint8_t* data_frame, uint16_t begin_add, uint16_t len);
extern MBRTU_Error mbrtu_holding_register_cb(uint8_t* data_frame, uint16_t begin_add, uint16_t len);

#define MBRTU_MES_ID_ERROR 		"ID ERROR\r\n"					//8+2
#define MBRTU_MES_FUNC_ERROR 	"OVERANGE FUNCTION\r\n"	//17+2
#define MBRTU_MES_ADD_ERROR 	"UNSUPPORT ADDRESS\r\n"	//17+2
#define MBRTU_MES_CRC_ERROR		"INCORRECT CRC\r\n"			//13+2

#endif
