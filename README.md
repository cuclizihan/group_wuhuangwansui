## Mandy

### 综合实践

#### 视频资料学习

- 内容提纲
  基础运行环境准备
  漏洞攻防环境现状
  漏洞攻防环境搭建
  漏洞攻击
  漏洞利用监测
  漏洞利用防御与加固



1. 基础运行环境准备

- 准备一个kali的虚拟机镜像
  网络设置--网络地址转换NAT（方便虚拟机有互联网连接）、仅主机网络（方便本地终端连接虚拟机）

- 开启虚拟机查看ip
  >ip a

  ![ip a](pic/ip_a.png)

  ip地址成功分配
  
  若有一块没有解决方式为
  >sudo vim /etc/network/interfaces

  文件修改如下，增添：
  ```
  allow-hotplug eth0
  iface eth0 inet dhcp

  allow-hotplug eth1
  iface eth1 inet dhcp

  ```
  然后
  >sudo ifdown eth0 && sudo ifup eth0

  >sudo ifdown eth1 && sudo ifup eth1

  查看发行版本信息：
  >lsb_release -a

  查看内核信息：
  >uname -a

- ssh服务
  
  >ssh kali@ip

  ![ssh](pic/ssh_error.png)
  
  linux没有开启ssh服务

  在虚拟机中，设置开机自启动
  >sudo systemctl enable ssh

  启动ssh
  >sudo systemctl start ssh

  查看
  >ps aux | grep ssh

  ![ssh](pic/ssh.png)

  重新连接
  ![ssh_connect](pic/ssh_connect.png)

  配置免密登录
  >ssh-copy-id -i ~/.ssh/con
  >ssh-copy-id -i ~/.ssh/id_rsa.pub kali@IP
  >ssh kali@IP

2. 漏洞攻防环境现状


3. 漏洞攻防环境搭建

- 虚拟机中：
  >git clone https://github.com/c4pr1c3/ctf-games
  >cd ctf-games
  >ls -l
  >cd fofpapro
  >ls

![git_clone](pic/git_clone.png)

- 安装docker
  更新
  >sudo apt update

  - 出现报错
    ```
    11 packages can be upgraded. Run 'apt list --upgradable' to see them.
    W: https://download.docker.com/linux/ubuntu/dists/zesty/InRelease: Key is stored in legacy trusted.gpg keyring (/etc/apt/trusted.gpg), see the DEPRECATION section in apt-key(8) for details.
    ```
   
    通过chatAI搜索问题解决办法得：
    下面是一套详细的解决步骤，用于解决“Key is stored in legacy trusted.gpg keyring”警告以及更新软件包的问题：

    1. 备份旧的 trusted.gpg 文件（如果有需要）
      >sudo cp /etc/apt/trusted.gpg /etc/apt/trusted.gpg.backup

      这样可以备份旧的 trusted.gpg 文件，以防需要恢复。

    2. 删除旧的 trusted.gpg 文件：
   
      >sudo rm /etc/apt/trusted.gpg

      这将删除旧的 trusted.gpg 文件，系统将在需要时重新生成。

    3. 下载并导入 Docker GPG 密钥：
   
      >curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/docker-archive-keyring.gpg >/dev/null

      这个命令将下载 Docker GPG 密钥，并将其导入 `/etc/apt/trusted.gpg.d/docker-archive-keyring.gpg` 文件中。

    4. 更新软件包列表：

      >sudo apt update

      这将更新软件包列表，同时导入了新版本的 Docker GPG 密钥。

    5. 查看可升级的软件包：

      >apt list --upgradable

      这个命令会列出所有可以升级的软件包，方便你进行选择。

    6. 升级软件包：
   
      >sudo apt upgrade

      运行此命令来升级可用的软件包。

    问题解决

    >sudo apt install -y docker docker-compose jq

  添加当前用户(可以使后面的很多docker命令不需要sudo)
  >sudo usermod -a -G docker kali

  在`/etc/docker/daemon.json`中添加
  ```
  {
      "registry-mirrors":["https://docker.mirrors.ustc.edu.cn/"]
  }
  ```
  
  重启docker镜像服务
  >systemctl restart docker

  - 出现报错：
    ```
    Job for docker.service failed because the control process exited with error code.
    See "systemctl status docker.service" and "journalctl -xeu docker.service" for details.
    ```
    查看Docker服务的状态：
    >systemctl status docker.service

    查看Docker服务的详细日志：
    >journalctl -xeu docker.service

    结果如下：
    ```
    The unit docker.service has entered the 'failed' state with result 'exit-code'.
    Jul 17 07:03:14 kali systemd[1]: Failed to start docker.service - Docker Application C> 
    ░░ Subject: A start job for unit docker.service has failed
    ░░ Defined-By: systemd
    ```
    
    通过ChatAI查询获得以下解决方式：

    - 清理残留进程和套接字：
        ```
        sudo systemctl stop docker.socket
        sudo systemctl stop docker.service
        sudo rm /var/run/docker.sock
        sudo systemctl start docker.service
        ```
        问题没有解决
    


    - 检查Docker配置：是否有格式错误（检查未发现）


    - 尝试重新安装Docker
        
        可能存在Docker软件包损坏或配置文件被破坏的情况。尝试重新安装Docker以修复可能的错误。运行以下命令

        ```
        sudo apt update
        sudo apt remove --purge docker.io
        sudo apt install docker.io
        ```

        执行到`sudo apt remove --purge docker.io`出现报错`E: dpkg was interrupted, you must manually run 'dpkg --configure -a' to correct the problem.`

        执行`dpkg --configure -a`进行修复

        重新执行docker安装操作，结果报错找不到docker包。。。。。

    - 尝试添加Docker官方源：
        ```
        sudo apt update
        sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        ```

    - 更新软件包：
        >sudo apt update

        又报错。。。。。。

        ```
        Err:3 https://download.docker.com/linux/debian kali-rolling Release
        404  Not Found [IP: 13.32.121.78 443]
        Reading package lists... Done
        E: The repository 'https://download.docker.com/linux/debian kali-rolling Release' does not have a Release file.
        N: Updating from such a repository can't be done securely, and is therefore disabled by default.
        N: See apt-secure(8) manpage for repository creation and user configuration details.
        ```

    决定恢复备份，重新做人。。


        




1. 漏洞攻击



5. 漏洞利用监测
6. 漏洞利用防御与加固