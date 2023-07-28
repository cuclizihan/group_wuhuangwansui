# 2023网络安全团队攻防实践

## 实验说明

团队分工跟练复现完成[网络安全(2021) 综合实验](https://www.bilibili.com/video/BV1p3411x7da/)，一人至少承担一种团队角色
- 红队：需完成漏洞存在性验证和漏洞利用。
- 蓝队威胁监测：漏洞利用的持续检测和威胁识别与报告。
- 蓝队威胁处置：漏洞利用的缓解和漏洞修复（源代码级别和二进制级别两种）。

## 完成目标

- [x] 完成基础环境搭建
- [x] 红队完成漏洞存在性验证和漏洞利用
- [x] 蓝队完成漏洞利用的持续检测
- [x] 蓝队进行对漏洞利用的缓解和修复建议

## 完成清单

- Log4j2远程命令执行漏洞
  - 漏洞存在性验证
  - 检验漏洞可利用性
      - 手动检测方式
      - 自动化检测方式
  - 漏洞利用的持续检测和威胁识别与报告

- 漏洞利用流量监测实战
  
- 跨网段渗透场景攻防
  - 捕获指定容器的上下行流量
  - 攻破靶标1
  - 建立立足点并攻破靶标2-4
  - 攻破终极靶标5

- 漏洞修复
  - log4j2 CVE-2021-44228漏洞修复
  - weblogic-CVE-2019-2725漏洞修复
  - Struts 2-CVE-2020-17530漏洞修复


## 团队分工

| 姓名 | id | 主要贡献 |
| :----: | :----: | :----: |
| 王祎琳 | willinggale | log4j2 CVE-2021-44228存在性、可利用性检验与持续检测；log4j2 CVE-2021-44228漏洞修复；跨网段多靶标攻防-攻破靶标1并发现靶标2-4；weblogic-cve-2019-2725漏洞修复 |
| 李子涵 | SparkleToy | Log4j2远程命令执行漏洞的存在性、可利用性检验与持续检测；跨网段渗透场景攻防-攻破靶标1-5；Struts 2-CVE-2020-17530漏洞临时修补建议|
| 米佳怡 | Mandy | Log4j2远程命令执行漏洞的存在性、可利用性检验与持续检测；漏洞利用流量监测实战；Log4j2漏洞的修复 |
| 戴灿 | cancan | log4j2漏洞检测存在性，可利用性，漏洞利用；weblogic-CVE-2019-2725漏洞复现（存在性，利用性，漏洞利用）、漏洞缓释；strust2漏洞的一些修复建议 |
| 方诗棋 | LongMouDYS | weblogic-CVE-2019-2725漏洞复现与修复 |
| 高思楠 | Cici | |