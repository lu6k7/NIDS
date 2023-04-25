from scapy.all import *
from netfilterqueue import NetfilterQueue
from mysql import dml,query
import os
import time
from pkthandler import pkthandler
from traffic import traffic
import re
import urllib.parse
from webtrack import web_check
from sqlsearch import sql_search
import json

 
#icmp攻击监测   
def icmp_Track(pkt,some_param):
    packet = IP(pkt.get_payload())
    choice=''
    allport=[]
#引入traffic.py:用于提取流量包的源ip,目的Ip,源端口,目的端口,tcp标志位,携带数据包
    srcip, dstip, proto, sport, dport, flag, content=traffic(packet)
#引入sqlsearch.py：用于收集数据库查询的信息，通过index定位值,尽可能减少数据库操作，countinfo:全部类型阈值  protocolinfo:全部攻击类型  portinfo:全部端口信息  timeinfo:全部时间信息 trackstatus:全部白名单类型 actionstatus:全部白名单行为
    countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus=sql_search(srcip)
#同上，一个为收集出战流量信息，一个为收集入站流量信息
    outcountinfo,outprotocolinfo,outportinfo,outtimeinfo,outtrackstatus,outactionstatus=sql_search(dstip)
    if packet.haslayer(ICMP):
        if int(packet["ICMP"].type)==8 or int(packet["ICMP"].type)==5:
            pkthandler(0,'icmp','icmp',0,int(some_param),pkt,packet,srcip,countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus)
        else:
            pkt.set_payload(bytes(packet))
            pkt.accept()
    else:
        pkt.set_payload(bytes(packet))
        pkt.accept()

#登录暴破
def login_Brute(pkt):
    packet = IP(pkt.get_payload())
    if packet.haslayer(TCP):
        choice=''
        allport=[]

        srcip, dstip, proto, sport, dport, flag, content=traffic(packet)

        countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus=sql_search(srcip)

        outcountinfo,outprotocolinfo,outportinfo,outtimeinfo,outtrackstatus,outactionstatus=sql_search(dstip)
        with open('brute.json','r') as fp:
            counts=0
            for i in range(len(countinfo)):
                counts+=int(countinfo[i])
            datas=json.load(fp)
            for k,v in datas.items(): 
                userdanger=v['danger']
                usercontent=v['content']
                userport=v['port']
                usertracktype=v['tracktype']
                userthreshold=v['threshold']
                allport.append(int(userport))
                if int(dport)==int(userport):
                    pkthandler(int(userdanger),usertracktype,usertracktype,dport,int(userthreshold),pkt,packet,srcip,countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus)
                elif int(sport) == int(userport):
                    if content and usercontent in content:
                        if query(f'select * from accesslog.ip where ip="{dstip}" and type={usertracktype} and action="login";'):
                            pass
                        else:
                            dml(f'insert into accesslog.ip(ip,time,type,action) value("{dstip}",{time.time()},{usertracktype},"login")')           
                    pkt.set_payload(bytes(packet))
                    pkt.accept()
            if int(sport) not in allport and int(dport) not in allport:
                    pkt.set_payload(bytes(packet))
                    pkt.accept()              
    else:
        pkt.set_payload(bytes(packet))
        pkt.accept()


#dos攻击
def dos_Track(pkt,some_param):
    packet = IP(pkt.get_payload())
    choice=''
    allport=[]

    srcip, dstip, proto, sport, dport, flag, content=traffic(packet)

    countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus=sql_search(srcip)

    outcountinfo,outprotocolinfo,outportinfo,outtimeinfo,outtrackstatus,outactionstatus=sql_search(dstip)
    if packet.haslayer(TCP):
        if 'dos' not in trackstatus and counts >=int(some_param):
                # print(f'{srcip}->{dport}->dos->drop\n')
                pkt.drop()
                inp=input(f'{srcip}疑似dos攻击,数据包默认丢弃,是否封锁该IP全部入站流量?输入1进行封锁，其他跳过!\n')
                if str(inp)=='1':
                    dml(f'insert into accesslog.ip(ip,time,type,action) value("{srcip}",{time.time()},"dos","blocked");')
                    cmd=f'iptables -I INPUT -s {srcip} -j DROP'
                    os.popen(cmd)
                    print('封锁成功')
                else:
                    dml(f'insert into accesslog.ip(ip,time,type,action) value("{srcip}",{time.time()},"dos","passed");')
                    print('跳过')
                    pass  
        elif 'dos' in trackstatus:
            # print(f'{srcip}->{dport}->dos->drop\n')
            pkt.drop()
        else:
            pkt.set_payload(bytes(packet))
            pkt.accept()
    else:
        pkt.set_payload(bytes(packet))
        pkt.accept()

#web攻击
def web_Track(pkt):
    packet = IP(pkt.get_payload())
    choice=''
    allport=[]

    srcip, dstip, proto, sport, dport, flag, content=traffic(packet)

    countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus=sql_search(srcip)

    outcountinfo,outprotocolinfo,outportinfo,outtimeinfo,outtrackstatus,outactionstatus=sql_search(dstip)
    if packet.haslayer(TCP) and int(dport) ==80 and content:    
        web_check(pkt,content,srcip,dstip,dport)
    elif packet.haslayer(TCP) and int(dport) ==80:
        pkthandler(0,'web','dos',dport,10000,pkt,packet,srcip,countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus)
    else:
        pkt.accept()

#url地址扫描   
def url_Scan(pkt,some_param):
    packet = IP(pkt.get_payload())
    choice=''
    allport=[]

    srcip, dstip, proto, sport, dport, flag, content=traffic(packet)

    countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus=sql_search(srcip)

    outcountinfo,outprotocolinfo,outportinfo,outtimeinfo,outtrackstatus,outactionstatus=sql_search(dstip)
    if packet.haslayer(TCP) and int(sport) ==80:
        if content and content.startswith('HTTP/1.1 404 Not Found'):
            if 'webscan' in outtrackstatus:
                # print(f'{sport}->{dstip}->404->drop')
                pkt.drop()
            else:
                pkthandler(0,'404','webscan',sport,some_param,pkt,packet,dstip,outcountinfo,outprotocolinfo,outportinfo,outtimeinfo,outtrackstatus,outactionstatus)
        else:
            pkt.accept() 
    else:
        pkt.accept() 
    
#端口扫描
def port_Scan(pkt,some_param):
    packet = IP(pkt.get_payload())
    choice=''
    allport=[]

    srcip, dstip, proto, sport, dport, flag, content=traffic(packet)

    countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus=sql_search(srcip)

    outcountinfo,outprotocolinfo,outportinfo,outtimeinfo,outtrackstatus,outactionstatus=sql_search(dstip)
    if packet.haslayer(TCP) and int(dport) not in allport:
                if srcip != some_param:
                    if 'portscan' in trackstatus:
                        # print(f'{srcip}->{dport}->portscan->drop')
                        pkt.drop()
                    else:
                        result=query(f'select port from accesslog.scan where ip="{srcip}"')
                        if len(result) >=100:
                            # print(f'{srcip}->{dport}->portscan->drop')
                            pkt.drop()
                            inp=input(f'{srcip}疑似端口扫描,是否封锁该IP全部入站流量?输入1进行封锁，其他跳过!')
                            if str(inp)=='1':
                                dml(f'insert into accesslog.ip(ip,time,type,action) value("{srcip}",{time.time()},"portscan","blocked")')
                                cmd=f'iptables -I INPUT -s {srcip} -j DROP'
                                os.popen(cmd)
                                print('封锁成功')                         
                            else:
                                dml(f'insert into accesslog.ip(ip,time,type,action) value("{srcip}",{time.time()},"portscan","passed")')
                                print('跳过')
                                pass
                        else:
                            res=query(f'select port from accesslog.scan where ip="{srcip}" and port={dport};')
                            if not res:
                                dml(f'insert into accesslog.scan(ip,port) value("{srcip}",{dport})')
                            # print(f'{srcip}->{dport}')
                            pkt.set_payload(bytes(packet))
                            pkt.accept()
                else:
                    pkt.set_payload(bytes(packet))
                    pkt.accept()
    else:
        pkt.set_payload(bytes(packet))
        pkt.accept()    

                
#整合版

