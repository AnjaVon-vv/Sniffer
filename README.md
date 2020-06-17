# 基于Libpcap和Qt5的嗅探器

&nbsp;&nbsp;&nbsp;&nbsp;基于Libpcap实现了一个简单的嗅探器，可分析各层协议并打印结果，实现了简单的流量统计，并将结果实时打印至界面控件中。

&nbsp;&nbsp;&nbsp;&nbsp;抓包与分析的实现部分参考了[这位大佬](https://blog.csdn.net/Sophisticated_/article/details/83338772) 的系列文章。

&nbsp;&nbsp;&nbsp;&nbsp;具体经验教程之后会写<font color=#9055A2><b>(多么鲜艳的Flag)</font>

## 开发环境与技术栈

- 开发环境：Ubuntu 18.04、CLion、QtCreator
- 运行须安装配置libpcap和Qt5

## 运行

&nbsp;&nbsp;&nbsp;&nbsp;环境配置完成后，进入build目录下打开终端，运行`./Sniffer` 即可。

&nbsp;&nbsp;&nbsp;&nbsp;P.S.也可通过cmake重新构建项目运行，或在Qt Creator中打开.pro运行。

## 文件功能

- protocol.h：定义各协议结构体
- analyze类：定义各协议解析函数
- widget类：Libpcap抓包函数、以太网数据帧解析（回调函数）、窗口功能
- sniffer类：无界面循环抓包实现（是widget的简化版，但运行时不需要）


## 效果展示
![show](https://img-blog.csdnimg.cn/20200617225517590.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3NpbmF0XzQxMTM1NDg3,size_16,color_FFFFFF,t_70)