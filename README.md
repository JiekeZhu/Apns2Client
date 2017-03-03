# Apn2Client
A simple APNs client built based on nghttp2 with Visual Studio 2015 for Windows platform.
https://github.com/JiekeZhu/Apn2Client

APNs Overview 官方文档
https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/APNSOverview.html#//apple_ref/doc/uid/TP40008194-CH8-SW1

Configure push notifications 创建证书、工程属性、
http://help.apple.com/xcode/mac/8.3/#/dev11b059073
https://github.com/Redth/PushSharp/wiki/How-to-Configure-&-Send-Apple-Push-Notifications-using-PushSharp


教程
http://blog.csdn.net/daydreamingboy/article/details/7977098
https://github.com/Redth/PushSharp/wiki/How-to-Configure-&-Send-Apple-Push-Notifications-using-PushSharp
https://developer.apple.com/library/prerelease/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/CommunicatingwithAPNs.html#//apple_ref/doc/uid/TP40008194-CH11-SW1 通信过程和架构

客户端App
1. 开启Notification授权
https://developer.apple.com/library/prerelease/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/SupportingNotificationsinYourApp.html#//apple_ref/doc/uid/TP40008194-CH4-SW1
2. 注册远程Notification推送
https://developer.apple.com/library/prerelease/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/HandlingRemoteNotifications.html#//apple_ref/doc/uid/TP40008194-CH6-SW1

APNs Provider 苹果消息推送提供者
C#版 HTTP/2 实现
https://github.com/Redth/HttpTwo
C#版 APNs Provider源码
https://github.com/redth/pushsharp
关键1
var config = new ApnsConfiguration (ApnsConfiguration.ApnsServerEnvironment.Sandbox, "push-cert.p12", "push-cert-pwd"); 
关键2
apns-topic = Bundle Id

Dependencies
1. apns2.c is the original example.  https://github.com/wardenlym/apns2-test
2. nghttp2 is the HTTP/2 C library. https://github.com/nghttp2/nghttp2
3. OpenSSL used comes from Poco C++ library. https://github.com/pocoproject/poco/tree/develop/openssl
Please check the project settings for include folders settings and library link settings.

Source code
Apns2Client.h/.cpp contains all the code.
1. Open nghttp2.sln with Visual Studio 2015.
2. Set Example as the startup project.
3. Please check the TODO labels and replace the needed parts with your own values.
4. Run.