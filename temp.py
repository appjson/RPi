#!/usr/bin/env python3
# coding=utf-8

import time
import Slog
import sys

TIME = 10

def set_time(int):
    global TIME
    TIME = int

def xprint(*args):
    text = [str(i) for i in args]
    text = "".join(text)
    print(text)
    Slog.log(text)
    

def get_cpu_temp():
    with open('/sys/class/thermal/thermal_zone0/temp') as f:
        cpu_temp = int(f.read())
    return cpu_temp / 1000


def main():
    init_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    xprint("=> %s"% init_time)
    xprint("=> Start logging...")
    time.sleep(2)
    try:
        while True:
            # xprint("=> Time: ", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            xprint("CPU Temperature: ", get_cpu_temp())
            time.sleep(TIME)
    except KeyboardInterrupt:
        xprint("=> Abort.")
        
        
if __name__ == '__main__':
    if (len(sys.argv) > 2):
        exit("Too many args")
    elif (len(sys.argv) < 2):
        pass
    else:
        argvv = int(sys.argv[1])
        if (argvv < 1 or argvv > 21600):
            exit("Bad number.")
        else:
            set_time(argvv)
    Slog.init("temp.log", True)
    main()
