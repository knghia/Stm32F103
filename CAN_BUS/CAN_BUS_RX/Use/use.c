
#include "use.h"
#include "main.h"
#include <stdio.h>

void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan)
{
	printf("2\r\n");
}

extern void setup(void){
 CAN_FilterTypeDef canfilterconfig;

  canfilterconfig.FilterActivation = CAN_FILTER_ENABLE;
  canfilterconfig.FilterBank = 18;
  canfilterconfig.FilterFIFOAssignment = CAN_FILTER_FIFO0;
  canfilterconfig.FilterIdHigh = 0x446<<5;
  canfilterconfig.FilterIdLow = 0;
  canfilterconfig.FilterMaskIdHigh = 0x446<<5;
  canfilterconfig.FilterMaskIdLow = 0x0000;
  canfilterconfig.FilterMode = CAN_FILTERMODE_IDMASK;
  canfilterconfig.FilterScale = CAN_FILTERSCALE_32BIT;
  canfilterconfig.SlaveStartFilterBank = 20;
	
  HAL_CAN_ConfigFilter(&hcan, &canfilterconfig);
	HAL_CAN_Start(&hcan);
	HAL_CAN_ActivateNotification(&hcan, CAN_IT_RX_FIFO1_MSG_PENDING);
	
	printf("Welcome !\r\n");
}

CAN_RxHeaderTypeDef rxHeader;
uint8_t canRX[8] = {0,0,0,0,0,0,0,0};
extern void loop(void){
	HAL_CAN_GetRxMessage(&hcan, CAN_RX_FIFO0, &rxHeader, canRX);
	HAL_Delay(500);
	printf("%02x ",canRX[0]);
	printf("%04x ",rxHeader.StdId);
	printf(".....\r\n");
}


