
#include "use.h"
#include "main.h"
#include <string.h>

CAN_TxHeaderTypeDef TxHeader;
CAN_FilterTypeDef canfilterconfig;
uint8_t TxData[8];
uint32_t TxMailbox;

extern void setup(void){

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
	
	TxHeader.IDE = CAN_ID_STD;
	TxHeader.StdId = 0x446;
	TxHeader.RTR = CAN_RTR_DATA;
	TxHeader.DLC = 2;

	TxData[0] = 50;  
	TxData[1] = 0xAA;
}

extern void loop(void){
	if (HAL_CAN_AddTxMessage(&hcan, &TxHeader, TxData, &TxMailbox) != HAL_OK)
	{
		 Error_Handler ();
	}
	HAL_Delay(500);
	HAL_GPIO_TogglePin(LED_GPIO_Port, LED_Pin);
}


