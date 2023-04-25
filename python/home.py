import textwrap
import colorama
from colorama import Fore, Style
from brute import *
from track import *
colorama.init() # 初始化颜色

def print_menu():
    print(Fore.BLUE + "欢迎使用NIDS流量监测系统!\n\n请选择要监测的攻击类型：")
    print(Fore.YELLOW + textwrap.dedent('''
        [1]  ICMP flood/重定向攻击                 [2]   非Web登录暴破
        [3]  Dos攻击                               [4]   url地址扫描
        [5]  端口扫描                              [6]   Web攻击
        [7]  以上全部监测                          ''') + Fore.GREEN + textwrap.dedent('[0]   退出\n')+ Style.RESET_ALL)

while True:
    print_menu()
    choice = input("请输入选项：")

    if choice == '1':
        print("您选择了 ICMP flood/重定向攻击监测\n")
        thre=input("请设置ICMP流量包的报警阈值(1小时内)\n")
        print("\n-----------------------正在监测中-----------------------")
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, lambda packet:icmp_Track(packet,thre))
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
    elif choice == '2':
        print("您选择了 非Web协议登录暴破监测\n")
        print("-----------------------正在监测中-----------------------")
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, login_Brute)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
    elif choice == '3':
        print("您选择了 Dos攻击监测\n")
        thre=input("请设置Dos攻击的报警阈值(1小时内)\n")
        print("\n-----------------------正在监测中-----------------------")
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, lambda packet:dos_Track(packet,thre))
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
    elif choice == '4':
        print("您选择了url地址扫描\n")
        thre=input("请设置url扫描的报警阈值(1小时内)\n")
        print("\n-----------------------正在监测中-----------------------")
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, lambda packet:url_Scan(packet,thre))
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
    elif choice == '5':
        print("您选择了端口扫描\n")
        yourip=input('请输入您的服务器ip来实现端口扫描监测\n')
        print("\n-----------------------正在监测中-----------------------")
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, lambda packet:port_Scan(packet,yourip))
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
    elif choice == '6':
        print("您选择了Web攻击监测\n")
        print("\n-----------------------正在监测中-----------------------")
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, web_Track)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
    elif choice == '7':
        print("您选择了全部监测\n")
        yourip=input('请输入您的服务器ip来实现端口扫描监测\n')
        print("\n-----------------------正在监测中-----------------------")
        # 创建NetfilterQueue对象
        nfqueue = NetfilterQueue()
        # 设置回调函数
        nfqueue.bind(1, lambda packet:process_packet1(packet,yourip))
        try:
            # 进入主循环
            nfqueue.run()
        except KeyboardInterrupt:
            pass
    elif choice == '0':
        print("感谢使用！")
        break
    else:
        print("无效的选项，请重新选择。\n")
