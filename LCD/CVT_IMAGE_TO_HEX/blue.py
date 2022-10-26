
import cv2

fname = "D:\\MCU\\STM32F103_Project\\Screen\\CVT_IMAGE_TO_HEX\\the_starry_night_wallpaper.png"

# img = Image.open(fname)
# if img.width != 128 or img.height != 160:
#     print("Error")

img_cv = cv2.imread(fname)
img = cv2.cvtColor(img_cv, cv2.COLOR_BGR2RGB)

print(128*160*2)

s = "const uint16_t test_img_128x160[20480] = { \r\n"

for r in range(0, 160):
    for c in range(0, 128):
        (R, G, B) = img[r][c]

        B = (B >> 3) & 0x1f
        G = ((G >> 2) & 0x3f) << 5
        R = ((R >> 3) & 0x1f) << 11
        color565 = (B | G | R)

        s += "0x{:02X},0x{:02X},".format(int(color565/256), color565%256)
    s += "\r"

s += "};"

f = open("D:\\MCU\\STM32F103_Project\\Screen\\CVT_IMAGE_TO_HEX\\data.txt", "w")
f.write(s)
f.close()
