from mysql import dml,query
import time
def sql_search(srcip):
    trackstatus=[]
    actionstatus=[]
    ipinfo=query(f'select type,action from accesslog.ip where ip="{srcip}";')
    for i in range(len(ipinfo)):
        trackstatus.append(ipinfo[i]['type'])
        actionstatus.append(ipinfo[i]['action'])
    info=query(f'select count,protocol,port,time from accesslog.info where ip="{srcip}";')
    countinfo=[]
    protocolinfo=[]
    portinfo=[]
    timeinfo=[]
    for i in range(len(info)):
        countinfo.append(info[i]['count'])
        protocolinfo.append(info[i]['protocol'])
        portinfo.append(info[i]['port'])
        timeinfo.append(info[i]['time'])
    return countinfo,protocolinfo,portinfo,timeinfo,trackstatus,actionstatus
# print(sql_search('192.168.1.134'))