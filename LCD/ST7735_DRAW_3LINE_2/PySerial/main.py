
import time
import serial
import numpy as np

try:
    connect = serial.Serial(port="COM9", baudrate=115200,timeout=0.1)
except serial.SerialException as error:
    print ("error : ",error)

while(1):
    x = [40,60,20]
    data = ":{:02x}{:02x}{:02x}\r\n".format(*x)
    print(data)
    connect.write(data.encode())
    time.sleep(0.2)