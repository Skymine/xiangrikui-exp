# 向日葵RCE漏洞一键批量检测工具

**注意：仅供企业内部安全隐患排查使用，禁止用于非法攻击，否则后果自负。**

## 使用方法（Python3环境）
1、解压后，在targets.txt中按行写入扫描目标IP：
```
172.16.11.1
172.16.11.2
172.16.11.3
172.16.11.4

```

2、打开终端，运行以下命令：

```
pip3 install requests
python3 exp.py
```

3、开始扫描，扫描结果保存在exp.py同目录的result.txt中
![[gif.gif]]
