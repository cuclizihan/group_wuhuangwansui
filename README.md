# 网络空间安全综合实践实验日志

## 纯净 Kali 首次启动后配置

由于已有可直接使用的kali虚拟机，故并未从0开始，只是在原有基础上添加了新的网卡，即host-only。

![网卡](网卡.png)

先检查网卡是否被启用

`ip -a`

使用vim进行文本编辑，启用网卡，用dhcp的方式来实现

`sudo vim /etc/network/interfaces`

之后输入配置代码

`allow-hotplug eth0` 
 
`iface eth0 inet dhcp`
 
`allow-hotplug eth1`
 
`iface eth1 inet dhcp`

之后运用传统保守管理网卡方式

`sudo ifdown eth0 && sudo ifup eth0`

`sudo ifdown eth1 && sudo ifup eth1`

接着

`cat /etc/os-release`

查看版本发行信息

`lsb_release -a`

查看内核信息

`uname -a`

关闭虚拟机改用无界面方式启动，并使用宿主机访问

`ssh kali@192.168.56.103`

发现没有办法访问。原因在于，在缺省情况下，kali没有开启ssh服务，再启用虚拟机界面开启

先设置开机自启动

`sudo systemctl enable ssh`

设置完开机自启动之后，未能直接启动，所以手动开启

`sudo systemctl start ssh`

验证开始

`ps aux | grep ssh`

确认开启，再换回宿主机运行

`ssh kali@192.168.56.103`

之后充值machine-id

`ls /etc/machine-id`

`cat /etc/machine-id`

`ls /var/lib/dbus/machine-id`

`cat /var/lib/dbus/machine-id`

之后重启确保生效

`sudo reboot`

## 安装 docker 和拉取镜像

搭建环境之前，首先检出仓库

`git clone https://github.com/c4pr1c3/ctf-games.git`

在ctf-games目录下进行操作

`cd ctf-games`

查看下属目录

`ls -l`

在ctf-games/fofapro目录下进行操作

`cd fofapro`

查看下属目录

`ls`

更新kali自带的镜像源

`sudo apt update`

安装docker

`sudo apt install -y docker.io docker-compose,jq`

再添加用户到docker组

`sudo usermod -a -G docker kali`

切换到root用户

`sudo su -`

改docker-hub镜像源为中科大镜像源

```
cat <<E0F > /etc/docker/deamon.json
 
 heredoc> {
          
          "registry-mirrors":["https://docker.mirrors.ustc.edu.cn/"]
          
          }

E0F
```

改完之后重启docker引擎服务

`sys/temctl restart docker`

退出root用户权限

`exit`

还需退出kali才能使权限生效，即退出再重新登录

`exit`

`ssh kali@092.168.56.103`

拉取vulfocus镜像

`docker pull vulfocus/vulfocus:latest`

![拉取](拉取.png)

## 快速上手 vulfocus

进入vulfocus目录

`cd ctf-games/fofapro/vulfocus`

启动vulfocus环境

`bash start.sh`

![bash](bash.png)

选择自己的host-only网卡。之后就可以通过地址在宿主机上访问vulfocus

![vulfocus](vulfocus.png)

## 跨网段多靶标攻防实验准备

首先由于官网已经不再提供下载和资源镜像分享，因此需要自己去设计构建相应的拓扑场景和镜像。

于是，先去下载了所需的几个镜像以及配置相应网卡，按照徐岩同学分享经验完成场景搭建

![场景](环境.png)

启动场景

![启动场景](启动场景.png)

验证端口是否一致

`docker ps`

![端口验证](端口验证.png)

启用tmux

`tmux`

![tmux](tmux.png)

输入相应容器名称进行监测

`container_name="e48de56e4c7c"

`docker run --rm --net=container:${container_name} -v ${PWD}/tcpdump/${container_name}:/tcpdump kaazing/tcpdump'

![监测](监测.png)

此处由于粗心大意，输错数字导致报错

![error1](error1.png)

至此，前期准备工作就绪

## 漏洞修复

通过对资料的查阅以及咨询别组同学，Weblogic-cve-2019-2725的漏洞源于在反序列化处理输入信息的过程中存在缺陷，未经授权的攻击者可以发送精心构造的恶意 HTTP 请求，利用该漏洞获取服务器权限，实现远程代码执行。

可以从Oracle官方漏洞复现源拿到漏洞镜像，根据Oracle的漏洞报告，此漏洞存在于异步通讯服务，通过访问路径

`/_async/AsyncResponseService`

判断不安全组件是否开启。wls9_async_response.war包中的类由于使用注解方法调用了Weblogic原生处理Web服务的类，因此会受该漏洞影响

继续分析漏洞是如何发送http请求从而获得权限的，在ProcessBuilder类中打下断点。首先程序是继承自HttpServlet的BaseWSServlet类，其中的service方法主要用于处理HTTP请求及其响应，通过HTTP协议发送的请求包封装在HttpServletRequest类的实例化对象var1中，调用BaseWSServlet中定义的内部类AuthorizedInvoke的run()方法完成传入HTTP对象的权限验证过程。若校验成功，则进入到SoapProcessor类的process方法中，通过调用HttpServletRequest类实例化对象var1的getMethod()方法获取HTTP请求类型，若为POST方法，则继续处理请求

HTTP请求发送至SoapProcessor类的handlePost方法：
