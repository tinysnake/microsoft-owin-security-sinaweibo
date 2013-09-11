Microsoft.Owin.Security.SinaWeibo
=================================

Middleware that enables an application to support [SinaWeibo](http://open.weibo.com/) OAuth 2.0 authentication workflow.

More information please visit: [Katana Project](http://katanaproject.codeplex.com/)

Please follow my weibo: [瘦不拉叽的SNAKE](http://weibo.com/tangfeifan) 

Install from nuget: 
`PM> Install-Package Microsoft.Owin.Security.SinaWeibo -Pre`([package url](https://www.nuget.org/packages/Microsoft.Owin.Security.SinaWeibo/))

Or search `Microsoft.Owin.Security.SinaWeibo` in Nuget package manager, and make sure you selected the Include Prerelease selection of the filter dropdownlist.

这是一个使用新浪账号的第三方账户登录的owin中间件.

更多内容请访问: [Katana Project](http://katanaproject.codeplex.com/)

请关注我的微博: [瘦不拉叽的SNAKE](http://weibo.com/tangfeifan)

从Nuget中安装:

在Nuget控制台中输入: `Install-Package Microsoft.Owin.Security.SinaWeibo -Pre`([package网址](https://www.nuget.org/packages/Microsoft.Owin.Security.SinaWeibo/))
或在Nuget的包管理器中搜索`Microsoft.Owin.Security.SinaWeibo`,并确保在包过滤的下拉菜单中选择Include Prerelease(包括预发行版)选项.
How to use:
===========

    //在你的"Startup"类的"Configure"方法中添加以下代码
    //别忘了添加Owin的命名空间.
    app.UseSinaWeiboAuthentication(
        appId: "your app id",
        appSecret: "your app secret");
        
最后:

1. 进入[新浪微博开放平台的管理中心页面](http://open.weibo.com/apps)选择你要使用的应用.

2. 点击左侧"应用信息"->"高级信息"

3. 点击右边的"OAuth2.0 授权设置"的编辑链接

4. 填写"授权回调页",填入你的网站地址(如:`http://weibo.com`),网址最后添加上`/signin-sinaWeibo`,最终组成类似`http://weibo.com/signin-sinaWeibo`的网址.

5. 点击"提交".