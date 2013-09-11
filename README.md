Microsoft.Owin.Security.SinaWeibo
=================================

Middleware that enables an application to support [SinaWeibo](http://open.weibo.com/) OAuth 2.0 authentication workflow.

More information please visit: [Katana Project](http://katanaproject.codeplex.com/)

Please follow my weibo: [here](http://weibo.com/tangfeifan) 

Install from nuget: 
`PM> Install-Package Microsoft.Owin.Security.SinaWeibo -Pre`([package url](https://www.nuget.org/packages/Microsoft.Owin.Security.SinaWeibo/))

Or search `Microsoft.Owin.Security.SinaWeibo` in Nuget package manager.


How to use:
===========


        
最后:

1. 进入[新浪微博开放平台的管理中心页面](http://open.weibo.com/apps)选择你要使用的应用.

2. 点击左侧"应用信息"->"高级信息"

3. 点击右边的"OAuth2.0 授权设置"的编辑链接

4. 填写"授权回调页",填入你的网站地址(如:http://weibo.com),网址最后添加上"/signin-sinaWeibo",最终组成类似"http://weibo.com/signin-sinaWeibo"的网址.

5. 点击"提交".