from mysql import dml,query
import time
def update_track(srcip,dstip,threshold):
    res=query(f'select * from accesslog.ip where ip="{srcip}" and type="web_track";')
    if not res:
        result=query(f'select count from accesslog.info where ip="{srcip}" and time > {int(time.time())-3600} and protocol="web_track";')
        if not result:
            dml(f'insert into accesslog.info(ip,time,count,protocol,port) value("{srcip}",{time.time()},1,"web_track",80);')
        else:
            dml(f'update accesslog.info set count=count+1,time={time.time()} where ip="{srcip}" and protocol="web_track";')
            if int(result[0]['count']) >=int(threshold):
                inp=input(f'{dstip}web攻击次数过多,是否封锁该IP全部入站流量?输入1进行封锁，其他跳过!')
                if str(inp)=='1':
                    dml(f'insert into accesslog.ip(ip,time,type,action) value("{srcip}",{time.time()},"web_track","blocked")')
                    cmd=f'iptables -I INPUT -s {srcip} -j DROP'
                    os.popen(cmd)
                    print('封锁成功')                         
                else:
                    dml(f'insert into accesslog.ip(ip,time,type,action) value("{srcip}",{time.time()},"web_track","passed")')
                    print('跳过')
                    pass
            else:
                pass
    else:
        pass
        
