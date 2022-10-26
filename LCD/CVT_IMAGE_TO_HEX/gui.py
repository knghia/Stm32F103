
# import cv2
# import numpy as np

# image = cv2.imread("the_starry_night_wallpaper.png")


# w,h,s = image.shape
# image = np.array(image)
# print(w,h,s)
# # str = ''

# # for r in range(w):
# #     a = ''
# #     for c in range(h):
# #         pixel = image[r][c]
# #         print(pixel)
# #         b = "0x{:02X},0x{:02X},0x{:02X}".format(*pixel)
# #         print(b)
# #         a+= "{"+b+"}, "
# #     str += "{"+a+"}, " + "\r\n"


# # #open text file
# # text_file = open("D:\MCU\STM32\STM32F103_Project\Screen\GUI\data.txt", "w")
 
# # #write string to file
# # text_file.write(str)
 
# # #close file
# # text_file.close()

# # print(str)

#!/usr/bin/env python

# vim: set ai et ts=4 sw=4:

from PIL import Image
import sys
import os
import cv2

fname = "D:\\MCU\\STM32\\STM32F103_Project\\Screen\\GUI\\.png"

# img = Image.open(fname)
# if img.width != 128 or img.height != 160:
#     print("Error")

img_cv = cv2.imread(fname)
img = cv2.cvtColor(img_cv, cv2.COLOR_BGR2RGB)

s = "const uint16_t test_img_128x160[61440] = { \r\n"

for r in range(0, 160):
    for c in range(0, 128):
        (R, G, B) = img[r][c]

        B = (B >> 2) & 0x3f
        G = ((G >> 2) & 0x3f)
        R = ((R >> 2) & 0x3f)

        s += "0x{:02X},0x{:02X},0x{:02X},".format(R,G,B)
    s += "\r"

s += "};"

f = open("D:\\MCU\\STM32\\STM32F103_Project\\Screen\\GUI\\data.txt", "w")
f.write(s)
f.close()