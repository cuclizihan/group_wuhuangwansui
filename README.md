# 2023网络安全团队攻防实践
## 项目介绍

[基础团队实践训练](https://c4pr1c3.github.io/cuc-wiki/cp/2023/index.html)：团队分工跟练复现完成 [网络安全(2021) 综合实验](https://www.bilibili.com/video/BV1p3411x7da/) 。以下按本次实践训练所涉及到的人员能力集合划分了以下团队角色。一人至少承担一种团队角色，老师将按照该角色的评价标准进行 `基于客观事实的主观评价` 。

* 红队：需完成漏洞存在性验证和漏洞利用。
* 蓝队威胁监测：漏洞利用的持续检测和威胁识别与报告。
* 蓝队威胁处置：漏洞利用的缓解和漏洞修复（源代码级别和二进制级别两种）。

上述能力的基本评分原则参考“道术器”原则：最基础要求是能够跟练并复现 [网络安全(2021) 综合实验](https://www.bilibili.com/video/BV1p3411x7da/) 中演示实验使用到的工具；进阶标准是能够使用课程视频中 **未使用** 的工具或使用编程自动化、甚至是智能化的方式完成漏洞攻击或漏洞利用行为识别与处置。

## 实验报告记录要求

* 实践训练过程中产生的文档、代码均采用 Github 的方式管理，每位团队成员在自己的分支中进行实验过程的记录，包括工作内容和学习收获，以使团队工作可视化；

## 纯净 Kali 首次启动后配置

由于已有可直接使用的kali虚拟机，故并未从0开始，只是在原有基础上添加了新的网卡，即host-only。

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

## 快速上手 vulfocus

进入vulfocus目录

`cd ctf-games/fofapro/vulfocus`

启动vulfocus环境

`bash start.sh`

选择自己的host-only网卡。之后就可以通过地址在宿主机上访问vulfocus
