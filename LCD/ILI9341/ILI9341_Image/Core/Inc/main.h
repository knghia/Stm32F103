/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.h
  * @brief          : Header for main.c file.
  *                   This file contains the common defines of the application.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2022 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32f1xx_hal.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */

/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/
/* USER CODE BEGIN EC */

/* USER CODE END EC */

/* Exported macro ------------------------------------------------------------*/
/* USER CODE BEGIN EM */

/* USER CODE END EM */

/* Exported functions prototypes ---------------------------------------------*/
void Error_Handler(void);

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
#define LCD_DB0_Pin GPIO_PIN_0
#define LCD_DB0_GPIO_Port GPIOA
#define LCD_DB1_Pin GPIO_PIN_1
#define LCD_DB1_GPIO_Port GPIOA
#define LCD_DB2_Pin GPIO_PIN_2
#define LCD_DB2_GPIO_Port GPIOA
#define LCD_DB3_Pin GPIO_PIN_3
#define LCD_DB3_GPIO_Port GPIOA
#define LCD_DB4_Pin GPIO_PIN_4
#define LCD_DB4_GPIO_Port GPIOA
#define LCD_DB5_Pin GPIO_PIN_5
#define LCD_DB5_GPIO_Port GPIOA
#define LCD_DB6_Pin GPIO_PIN_6
#define LCD_DB6_GPIO_Port GPIOA
#define LCD_DB7_Pin GPIO_PIN_7
#define LCD_DB7_GPIO_Port GPIOA
#define LCD_DB8_Pin GPIO_PIN_0
#define LCD_DB8_GPIO_Port GPIOB
#define LCD_DB9_Pin GPIO_PIN_1
#define LCD_DB9_GPIO_Port GPIOB
#define LCD_DB10_Pin GPIO_PIN_2
#define LCD_DB10_GPIO_Port GPIOB
#define SPI2_CS_Pin GPIO_PIN_12
#define SPI2_CS_GPIO_Port GPIOB
#define FLASH_CS_Pin GPIO_PIN_8
#define FLASH_CS_GPIO_Port GPIOA
#define LCD_RST_Pin GPIO_PIN_9
#define LCD_RST_GPIO_Port GPIOA
#define LCD_WR_Pin GPIO_PIN_10
#define LCD_WR_GPIO_Port GPIOA
#define LCD_CS_Pin GPIO_PIN_11
#define LCD_CS_GPIO_Port GPIOA
#define LCD_RS_Pin GPIO_PIN_12
#define LCD_RS_GPIO_Port GPIOA
#define LCD_DB11_Pin GPIO_PIN_3
#define LCD_DB11_GPIO_Port GPIOB
#define LCD_DB12_Pin GPIO_PIN_4
#define LCD_DB12_GPIO_Port GPIOB
#define LCD_DB13_Pin GPIO_PIN_5
#define LCD_DB13_GPIO_Port GPIOB
#define LCD_DB14_Pin GPIO_PIN_6
#define LCD_DB14_GPIO_Port GPIOB
#define LCD_DB15_Pin GPIO_PIN_7
#define LCD_DB15_GPIO_Port GPIOB
/* USER CODE BEGIN Private defines */

/* USER CODE END Private defines */

#ifdef __cplusplus
}
#endif

#endif /* __MAIN_H */
