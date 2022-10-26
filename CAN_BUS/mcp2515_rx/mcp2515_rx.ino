#include <SPI.h>              //Library for using SPI Communication 
#include <mcp2515.h>          //Library for using CAN Communication (https://github.com/autowp/arduino-mcp2515/)

struct can_frame canMsg;
MCP2515 mcp2515(10);                 // SPI CS Pin 10
void setup()
{
  Serial.begin(9600);                //Begins Serial Communication at 9600 baudrate
  SPI.begin();                       //Begins SPI communication
  
  mcp2515.reset();
  mcp2515.setBitrate(CAN_500KBPS, MCP_8MHZ); //Sets CAN at speed 500KBPS and Clock 8MHz
  mcp2515.setNormalMode();                  //Sets CAN at normal mode
}
 
 
void loop()
{
  if (mcp2515.readMessage(&canMsg) == MCP2515::ERROR_OK) // To receive data (Poll Read)
  {
    Serial.print(canMsg.can_id);Serial.print('\t');
    Serial.print(canMsg.can_dlc);Serial.print('\t'); 
    
    Serial.print(canMsg.data[0]);Serial.print('\t');
    Serial.print(canMsg.data[1]);Serial.print("\r\n");
  }
  delay(500);
}
