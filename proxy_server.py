import sys
import os
import random
import subprocess
import string
import json
import logging
import atexit
import signal
import traceback
import sched
import time
from random import randrange, sample
from subprocess import CalledProcessError

password_list = ['z','y','x','w','v','u','t','s','r','q','p','o','n','m','l','k','j','i','h','g','f','e','d','c','b','a',
                 '0','1','2','3','4','5','6','7','8','9',
                 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'
                 ]

host = ''

while True:
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
        from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, \
                asyncdns, manager
        import requests
        break
    except ImportError:
        try:
            process = subprocess.check_output("pip install shadowsocks & pip install requests",shell=True)
        except CalledProcessError:
            process = subprocess.check_output("pip3 install shadowsocks & pip3 install requests",shell=True)
    time.sleep(1)



default_shadowsock_config = {
    "server":"0.0.0.0",
    "port_password":{
        '9385':'z2255611z'
    },
    "timeout":600,
    "method":"aes-256-cfb",
    "fast_open":True,
    "workers":1
}

import socket

child = None

def get_host_ip():
    output = subprocess.check_output('echo $(curl -s https://txt.go.sohu.com/ip/soip)| grep -P -o -i "(\d+\.\d+.\d+.\d+)"',shell=True)
    return output.decode().rstrip('\r\n')


def is_port_used(port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        s.connect(('127.0.0.1',int(port)))
        s.shutdown(2)
        return True
    except:
        return False


def get_unbind_local_port():
    while True:
        port = random.randint(10001, 10001 + 6500)
        if not is_port_used(port):
            return port
    return None

from signal import *


def kill_proxy_process():
    try:
        subprocess.check_output("sudo ufw status", shell=True)
        subprocess.check_output("ps aux|grep {}|awk -F\\' '{{print $2}}'|xargs kill -9".format("shadowsock.json"), shell=True)
        subprocess.check_output("ps aux|grep {}|awk -F\\' '{{print $2}}'|xargs kill -9".format("proxy_server"),shell=True)
    except:
        pass

if __name__ == "__main__":


    try:
        subprocess.check_output("sudo ufw status", shell=True)
        subprocess.call("ufw disable",shell=True)
    except:
        pass

    kill_proxy_process()

    ss_config = default_shadowsock_config.copy()
    ss_config['ip'] = get_host_ip()

    port_nums = random.randint(1,5)
    for index in range(port_nums):
        port = get_unbind_local_port()
        ss_config['port_password'][port] = "".join(sample(password_list, 16)).replace(' ', '')
        #subprocess.call("sudo ufw allow {}".format(port), shell=True)

    current_path = os.path.abspath('.')
    full_path = current_path + '/shadowsock.json'
    config_handle = open(full_path,'w')

    def term_sig_handler(signum, frame):
        print('catched singal: %d' % signum)
        sys.exit()

    def atexit_fun(*args,**kwargs):
        print('proxy exit')
        kill_proxy_process()
        exc_type, exc_value, exc_tb = sys.exc_info()
        traceback.print_exception(exc_type, exc_value, exc_tb)
        sys.exit()

    atexit.register(atexit_fun)

    try:
        for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
            signal(sig, atexit_fun)
    except:
        pass

    print("#### shadowsock config:",ss_config)
    if config_handle.write(json.dumps(ss_config)):
        config_handle.close()
        print("### start shadowsock")
        cmd = "ssserver -c {} start".format(full_path)
        child = subprocess.Popen(cmd,shell=True)

        print("##start  child wait")
        child.wait()
        print("## finish")
