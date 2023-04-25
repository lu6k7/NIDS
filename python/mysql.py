import pymysql
import time
from  pymysql.cursors import DictCursor
def dml(sql):
    con=con=pymysql.connect(host='127.0.0.1',port=3306,user='root',password='',database='accesslog',charset='utf8')
    cursor = con.cursor(cursor=DictCursor)
    cursor.execute(sql)
    con.commit()
    con.rollback()
    cursor.close()
    con.close()
def query(sql):
    con=con=pymysql.connect(host='127.0.0.1',port=3306,user='root',password='',database='accesslog',charset='utf8')
    cursor = con.cursor(cursor=DictCursor)
    cursor.execute(sql)
    result=cursor.fetchall()
    con.rollback()
    cursor.close()
    con.close()
    return result

        