#!/usr/bin/python
__author__ = 'oleh.hrebchuk'

import subprocess
import re
import os
from sys import argv

total = len(argv)

try:
    dir = str(argv[1])
    port = str(argv[2])
    host = str(argv[3])
    serviname = str(argv[4])
    namelog = str(argv[5])

except:
    dir = os.chdir('/var/')
    port = "3389"
    host = "127.0.0.1"
    serviname = "ms-wbt-server"
    namelog = "log.txt"

if total < 6 or total > 6:
    print ("Params: /dir_log/, port_scann, host_scann, service_name, name_log")

nmap_params = "nmap -sT -Pn -n -p {} {}".format(port, host)
pattern = re.compile(r"^{}/tcp.(\w+).?{}$".format(port, serviname))
get_status = subprocess.check_output("{}".format(nmap_params),
                                     stderr=subprocess.STDOUT,
                                     shell=True
                                     )


def write_log(val):
    with open('{}{}'.format(dir,namelog), 'w')as f_log:
        f_log.write(val + '\n')


def main():
    list_com = [line for line in get_status.split('\n') if pattern.findall(line)]
    if 'open' in list_com[0]:
        write_log('1')
        print('1')
    else:
        write_log('0')
        print('0')


if __name__ == "__main__":
    main()
