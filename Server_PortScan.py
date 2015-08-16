#本脚本利用公司IPV4的HTML网页内容进行分析扫描
#用于确认服务器开放那些端口帮助运维人员进行端口的管理
#本脚本获得的数据将会保存到excel表格之中，也可以用于定期的自动化扫描
#帮助确认
#本脚本使用了多个库
#re用于正则表达式，IPy用户IP地址的抽取和csdr的转换
#nmap用于端口扫描，xlwt用于操作excel，安装方法可以google
#本脚本的实验环境是Windows操作系统安装了 nmap 6.4.9版本具体配置环境自行google
#本脚本代码可以轻松移植到其他平台请按照文档说明阅读理解并修改

import string
import re
import os
from IPy import IP
import IPy
import nmap
import xlwt
import xlrd
#定义excel表格中的两个向量X，Y在插入表格的时候会用

X_AXIS=0
Y_AXIS=0
#初始化一个excel对象并初始化一个table
file_excel=xlwt.Workbook()
table=file_excel.add_sheet("port scan")


#save_excel函数用于在检测到open端口的时候调用把开启了端口IP地址和开放端口信息的数据保存起来
def sava_excel(str_ip,port_list_open):
	global X_AXIS
	global Y_AXIS
	table.write(X_AXIS,Y_AXIS,str_ip)
	X_AXIS=X_AXIS+1
	for item_excel_number in port_list_open:
		table.write(X_AXIS,Y_AXIS,item_excel_number)
		X_AXIS=X_AXIS+1	


def re_ports(line):

	re_open_ports=re.compile(r'\d+:\s{\'state.+?}')
	ports_list=re_open_ports.findall(line)
	
	port_list_open=[]
	
	for item in ports_list:
		if ("open" in item):
			port_list_open.append(item)
			
		else:
			pass
	
	return port_list_open


#根据HTML网页的内容把里面的IP地址抽取出来，抽取出来的格式是x.x.x.x/x的csdr格式
def get_ip(file_html):
	try:
		re_ip=re.compile(r'\d+\.\d+\.\d+\.\d+\/\d\d')
		ip_list=re_ip.findall(file_html)

	except Exception, e:
		raise e	
	
	return ip_list


#进行端口扫描的函数，传递的为一个IP地址
def nmap_scan(x):
	try:
		str_ip=IPy.IP(x).strNormal()
		nmapscan=nmap.PortScanner()
		str_item_port=''		
		str_item_port=nmapscan.scan(hosts=str_ip,arguments='-Pn')
		string_port=str(str_item_port)		
		port_list_open=re_ports(string_port)
		print str_item_port
		
		if (len(port_list_open)==0):
			pass
		else:
			try:
				str_ip=str(x)
				sava_excel(str_ip,port_list_open)

			except Exception, e:
				raise e
			finally:
				pass

	except Exception, e:
		raise e


#把csdr格式的IP地址格式转化为一个个IP并返回一个list
def ip_csdr(x):
	ip=IPy.IP(x)
	ip_list_csdr=[]
	for ip_item in ip:	
		ip_list_csdr.append(ip_item)

	return ip_list_csdr


if __name__ == '__main__':
	full_ip_list=[]
	real_ip_list=[]
	#定义我们保存的网页路径，这里简化了方法
	#我们先把我们地址池的HTML网页保存到本地
	file_path="C:/Users/D2015085/Desktop/IPv4.html"
	#获取csdr格式的IP地址并保存到full_ip_list中然后关闭文件
	try:
		if (os.path.exists(file_path)):
			file_object=open(file_path)
			file_html=file_object.read()
			full_ip_list=get_ip(file_html)
	except Exception, e:
		raise e
	finally:
		file_object.close()
	#将获得的full_ip_list进行处理
	#因为我们获取到的full_ip_list地址中包含很大一部分局域网的地址
	#我们的任务是收集我们外网开放的端口所以把真正外网的IP的csdr格式的地址抽取出来就好了
	#把抽取出来的外网csdr地址保存在real_ip_list中
	#这里选用的鉴别方法是根据末尾的mac掩码来进行判别可能有不准的地方会持续迭代这部分

	for var_item in full_ip_list:
		last_two_number=var_item[-2:]
		number=int(last_two_number)
		
		if (number>=int(25)):
			if var_item in real_ip_list:
				pass
			else:
				real_ip_list.append(var_item)
			
		else:
			pass
	#声明一个ip_pool_list
	#作为我们抽取的每个真实外网IP地址的地址池列表
	ip_pool_list=[]
	for x in real_ip_list:
		ip_csdr_list=[]
		ip_csdr_list=ip_csdr(x)
		for ip_each in ip_csdr_list:
			ip_pool_list.append(ip_each)
	#根据上面获取到的地址池IP地址循环扫描，这部分后面可能会采取多线程处理
	#使得scan的速度可以提高
	for ip_in_pool in ip_pool_list:
		nmap_scan(ip_in_pool)
	#关闭保存我们扫描获取到的excel文件
	file_excel.save("scanport.xls")	