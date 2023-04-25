from scapy.all import *

#可以检测常规的协议或应用类攻击，如ICMP、TCP、DOS类、扫描类、暴破类，如SSH(22)、Redis、MySQL、Web 等
#可以检测常规的Web攻击，如SQLi、XSS、木马上传、文件包含、CSRF、SSRF、XXE、反序列化、DNS带外、命令注入等
def traffic(packet):
    # 源IP
    try:
        srcip = str(packet["IP"].src)
    except:
        srcip =None   
    # 目的IP
    try:
        dstip = str(packet["IP"].dst)
    except:
        dstip =None     
    # 源端口
    try:
        sport = str(packet["TCP"].sport)
    except:
        sport ='0'
    # 协议:udp/tcp/icmp
    try:
        proto=str(packet["IP"].proto)
    except:
        proto =None
    # 目的端口
    try:
        dport = str(packet["TCP"].dport)
    except:
        dport ='0'
    # tcp标志位
    try:
        flag = str(packet["TCP"].flags)
    except:
        flag =None   
    # 数据正文
    try:
        content = str(packet["Raw"].load.decode(errors='ignore'))
    except:
        content =None
    return srcip, dstip, proto, sport, dport, flag, content