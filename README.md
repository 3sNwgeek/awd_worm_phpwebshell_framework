# awd_worm_phpwebshell_framework
awd-php-webshell awd比赛落地RPG，快速吃鸡框架，快速批量持续控制靶机，所有php文件皆webshell，持续改进完善中。
详情介绍请参考合天智汇文章：  
蠕虫webshell代码功能详情：[《基于AWD比赛的蠕虫webshell(一)》](https://mp.weixin.qq.com/s/8jrb_q8oysSfC2CC6m13bw)  
蠕虫webshell复活框架：[《基于AWD比赛的蠕虫webshell(二)》](https://mp.weixin.qq.com/s/R9TDu5QdUnPUtfV-_v0iCw)  
蠕虫webshell适配msf、前端传播与反渗透：[《基于AWD比赛的蠕虫webshell(三)》](https://mp.weixin.qq.com/s/sZYKS3gN_bXqMA_9YXzuhw)  
蠕虫webshell代码混淆：[《基于AWD比赛的蠕虫webshell(四)》](https://mp.weixin.qq.com/s/J9qkq6eVxfHIUt2XjXT2Nw)

实际用例是这样的：  
假设shell.php已经上传到目录，上传目录为upload，ip为192.168.1.1  

感染功能  
1.浏览器访问 http://192.168.1.1/upload/shell.php 会自动跳转带参数?_访问(带参数访问自动重写所有php文件)  
2.python requests访问 http://192.168.1.1/upload/shell.php?_  

命令执行  
1.使用 php_Excute_Client_light_vision.py 改好头部要执行命令与路径即可执行  

复活框架  
1.更改upupup()函数，return蠕虫马的url即可  

反渗透  
1.在文件末尾插入hook.js，结合beef框架利用
