#!/usr/bin/env python3
# coding=utf-8

import RPi.GPIO as GPIO
import time

# 控制风扇的GPIO
FAN_GPIO = 11
# 低温阈值，低于它则关闭风扇
MIN_TEMP = 35
# 高温阈值，高于它则全速运转
MAX_TEMP = 55
# 多长时间读取一次CPU温度，单位秒
SAMPLING = 10


# 获得温度
def get_cpu_temp():
    with open('/sys/class/thermal/thermal_zone0/temp') as f:
        cpu_temp = int(f.read())
    return cpu_temp / 1000


def main():
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BOARD)
    GPIO.setup(FAN_GPIO, GPIO.OUT)

    # 初始化PWM的频率，frequency=50Hz
    pwm = GPIO.PWM(FAN_GPIO, 50)
    # 为防止风扇卡死，开机全速运行n秒
    pwm.start(100)
    time.sleep(5)
    pwm.stop()

    try:
        while True:
            temp = get_cpu_temp()
            print('CPU temperature: ', temp)
            if temp < MIN_TEMP:
                # 低于低温阈值，则关闭风扇
                print('- Fan stopped.')
                pwm.stop()
            elif temp > MAX_TEMP:
                # 超过高温阈值，则全速运行
                print('- Fan full-speed running.')
                pwm.start(100)
            else:
                # 在低温阈值和高温阈值之间时，则根据占空比使用PWM控制风扇转速。
                dc = (temp - MIN_TEMP) * 100 / (MAX_TEMP - MIN_TEMP)
                pwm.start(dc)
                print('PWM duty cycle: %.3f'% dc)
            # 设置采样频率
            time.sleep(SAMPLING)
    except KeyboardInterrupt:
        pass

    pwm.stop()
    GPIO.cleanup()


if __name__ == '__main__':
    main()
