# —*—coding:UTF-8 -*-
# time:2019.12.11
# author:clarayuki
#python webshell_detector.py -r path -f "php"

import optparse
import os
import logging
import re
import time
import base64
import hashlib

_asp_blacklist=[]
_php_blacklist=[]
_jsp_blacklist=[]
_files_path=[]
_hash_list=[]


_regex="str_replace|preg_replace.*\/e|`.*?\$.*?`|passthru|shell_exec|exec|base64_decode|eval|system|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source"


#读取各类黑名单列表中的数据
def readblack(file,onelist):
    file=os.path.abspath(file)
    with open(file,'r') as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith('#'):
                continue
            else:
                onelist.append(line)
    return onelist

readblack("blacklist/jsp_blacklist.txt",_jsp_blacklist)
readblack("blacklist/asp_blacklist.txt",_asp_blacklist)
readblack("blacklist/php_blacklist.txt",_php_blacklist)
readblack("blacklist/hash_list.txt",_hash_list)

# 获取目录下符合要求的文件的绝对路径
def getwalk(path,suffix):
    for rootdir,subdir,file_name in os.walk(path):
        absolute_path = os.path.abspath(rootdir)
        for i in file_name:
            if i.split('.')[1] in suffix.split('|'):
                _files_path.append(os.path.join(absolute_path,i))
        for j in subdir:
            getwalk(os.path.join(absolute_path,j),suffix)
    return _files_path

#获取文件具体信息 os.stat可获取文件信息
def fileinfo(path):
    (mode,ino,dev,link,uid,gid,size,atime,mtime,ctime)=os.stat(path)
    atime=time.strftime("%Y--%m--%d %H:%M:%S", time.localtime(atime))
    mtime=time.strftime("%Y--%m--%d %H:%M:%S", time.localtime(mtime))
    ctime=time.strftime("%Y--%m--%d %H:%M:%S", time.localtime(ctime))
    info="模式为%s，节点号为%s，驻留的设备为%s，链接数为%s，所有者的用户ID%s，所有者的组ID%s，大小%s，上次访问%s，最后修改%s，第一次创建%s"%(mode,ino,dev,link,uid,gid,size,atime,mtime,ctime)
    return info

class shelldetect():
    #通过文件名方式
    def filename(self,suffix,file_name):
        if suffix=='asp':
            if file_name in _asp_blacklist:
                return True
        elif suffix=='php':
            if file_name in _php_blacklist:
                return True
        elif suffix=='jsp':
            if file_name in _jsp_blacklist:
                return True
        return False

    #通过文件内容
    def filecontent(self,content):
        match_result=re.findall(_regex,content)
        if match_result:
            return match_result
        return False

    #判断是否加密
    def judgeencode(self,content):
        try:
            res=base64.b64decode(content)
            if base64.b64encode(res)==content:
                return "base64加密"
            else:
                return False
        except:
            return False

    #需要收集常见shell的md5值
    def judgewebshell(self,file):
        # hash检测 md5是验证文件完整性，一般webshell都会修改再使用
        def md5sum(file):
            m = hashlib.md5()
            with open(file) as fp:
                #运送原材料
                m.update(fp.read().encode('utf-8'))
                #产生hash值
                return m.hexdigest()
        for i in _hash_list:
            if i==md5sum(file):
                return True
            else:
                return False


def main():
    logging.basicConfig(level=logging.INFO,format='%(asctime)s-%(levelname)s-%(message)s')
    logger=logging.getLogger()

    parser=optparse.OptionParser()
    parser.add_option("-r","--route--",dest="route",metavar="PATH",help="请输入目录路径")
    parser.add_option("-f","--format--",dest="format",default="ASP|JSP|PHP",metavar="SUFFIX NAME",help="请输入查询哪一类文件")
    options,args=parser.parse_args()

    if options.route==None:
        logging.info("未输入路径")
        return

    if not os.path.isdir(options.route) or not os.path.exists(options.route):
        logging.info("该路径不存在或不是目录")
        return
    logging.info("开始检测......请稍等@*@")
    getwalk(options.route,options.format)
    shelldetector=shelldetect()

    for file in _files_path:
        suffix=file.split('.')[1]
        file_name=file.split('.')[0].split('/')[-1]
        info=fileinfo(file)
        with open(file,'r') as f:
            content=f.read()

        if shelldetector.filename(suffix,file_name):
            logging.info("%s文件名匹配为已知webshell,文件信息为%s"%(file,fileinfo(file)))
        if shelldetector.filecontent(content):
            logging.info("%s文件匹配到%s的内容，文件信息为%s"%(file,shelldetector.filecontent(content),fileinfo(file)))

        if shelldetector.judgeencode(content):
            logging.info("%s文件%s，可能是webshell，文件信息为%s"%(file,shelldetector.judgeencode(content),fileinfo(file)))
        
        if shelldetector.judgewebshell(file):
            logging.info("根据md5值%s文件为已知webshell，文件信息为%s"%(file,fileinfo(file)))


    logging.info("检测完成......@*@")

if __name__=="__main__":
    main()
