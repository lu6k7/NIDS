from scapy.all import *
from netfilterqueue import NetfilterQueue
from mysql import dml,query
import os
import time
from pkthandler import pkthandler
from traffic import traffic
import re
import urllib.parse
from pkthandler import pkthandler
from websql import update_track
import json
from sqlsearch import sql_search
def web_check(pkt,content,srcip,dstip,dport):
    bol=0
    countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus=sql_search(srcip)
# 检查是否为HTTP POST请求
        # 获取POST请求的载荷
    content = urllib.parse.unquote(content)
    content= content.lower()
    head = content.split('\r\n\r\n')[0]
    try:               
        payload = content.split('\r\n\r\n')[1]
    except:
        payload='None'

    with open('payload.json','r') as fp:
        datas=json.load(fp)
        for tp,val in datas.items():
            if tp=='csrf':
                pattern=re.compile(f'{val["payload"]}+{dstip}')
            else:
                pattern=re.compile(val['payload'])
            if pattern.findall(content):
                if 'web_track' in protocolinfo and int(time.time())-int(timeinfo[protocolinfo.index('web_track')])>=3:
                    print(f'ip:{srcip}疑似进行{tp}')
                update_track(srcip,dstip,val["threshold"])
                bol=1
        if bol ==1:
            pkt.drop()                    
        else:
            pkthandler(0,'web','dos',dport,5000,pkt,packet,srcip,countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus)
