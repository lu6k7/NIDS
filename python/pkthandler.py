from scapy.all import *
from netfilterqueue import NetfilterQueue
from mysql import dml,query
import os
import time
from sqlsearch import sql_search
#入站流量统计访问次数


def pkthandler(track,protocol,types,port,checknum,pkt,packet,srcip,countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus):
#看白名单是否有ip
    if types in trackstatus:
        if actionstatus[trackstatus.index(types)] =='login':
            # print(f'{srcip}->{port}->{protocol}->放行')
            pkt.accept()
        else:
            # print(f'{srcip}->{port}->{protocol}->drop')
            pkt.drop()
    elif int(port)==22:
        cmd=f'grep "Accepted " /var/log/secure | awk \''+'{print $11}'+f'\' | sort | grep -E \'{srcip}\''
        res=os.popen(cmd).read()
        if res:
            dml(f'insert into accesslog.ip(ip,time,type,action) value("{srcip}",{time.time()},"{types}","login")')
            # print(f'{srcip}->{port}->{protocol}->放行')
            pkt.accept()
        else:
            pass
#看数据库是否已有ip入侵信息
    if types not in trackstatus and protocol in protocolinfo:
        #大于阈值
        if int(countinfo[protocolinfo.index(protocol)]) >= checknum:
            #超过一小时
            if int(timeinfo[protocolinfo.index(protocol)])-time.time() >=3600:
                dml(f'update accesslog.info set count=1,time={time.time()} where ip="{srcip}" and protocol="{protocol}";')
                #攻击还是暴破类型
                if int(track) == 1:
                    # print(f'{srcip}->{port}->{protocol}->drop')
                    pkt.drop()
                elif int(track) == 0:
                    # print(f'{srcip}->{port}->{protocol}')
                    pkt.accept()                        
            else:
                # print(f'{srcip}->{port}->{protocol}->drop\n')
                pkt.drop()
                inp=input(f'{srcip}短时间内{protocol}访问超过{checknum}次,当前协议数据包默认丢弃,是否封锁该IP全部入站流量?输入1进行封锁，其他跳过!\n')
                if str(inp)=='1':
                    dml(f'insert into accesslog.ip(ip,time,type,action) value("{srcip}",{time.time()},"{types}","blocked");')
                    cmd=f'iptables -I INPUT -s {srcip} -j DROP'
                    os.popen(cmd)
                    print('封锁成功')                         
                else:
                    dml(f'insert into accesslog.ip(ip,time,type,action) value("{srcip}",{time.time()},"{types}","passed");')
                    print('跳过')
                    pass  
        else:
            #小于阈值且大于一小时
            if int(timeinfo[protocolinfo.index(protocol)])-time.time()>=3600:
                dml(f'update accesslog.info set count=1,time={time.time()} where ip="{srcip}" and protocol="{protocol}";')
                # print(f'{srcip}->{port}->{protocol}')
                pkt.accept()
            else:
            #小于阈值
                dml(f'update accesslog.info set count=count+1,time={time.time()} where ip="{srcip}" and protocol="{protocol}";')
                # print(f'{srcip}->{port}->{protocol}')
                pkt.accept()  
#数据库没有信息
    elif types not in trackstatus and protocol not in protocolinfo:
        dml(f'insert into accesslog.info(ip,count,time,protocol,port) value("{srcip}",1,{time.time()},"{protocol}",{port});')
        # print(f'{srcip}->{port}->{protocol}')
        pkt.accept()                           
