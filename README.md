# Apn2Client
A simple APNs client built based on nghttp2 with Visual Studio 2015 for Windows platform.<p>
https://github.com/JiekeZhu/Apn2Client <p>
<p>
APNs Overview 官方文档<p>
https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/APNSOverview.html#//apple_ref/doc/uid/TP40008194-CH8-SW1<p>
<p>
Configure push notifications 创建证书、工程属性<p>
http://help.apple.com/xcode/mac/8.3/#/dev11b059073 <p>
https://github.com/Redth/PushSharp/wiki/How-to-Configure-&-Send-Apple-Push-Notifications-using-PushSharp <p>
<p>
<p>
教程<p>
http://blog.csdn.net/daydreamingboy/article/details/7977098 <p>
https://github.com/Redth/PushSharp/wiki/How-to-Configure-&-Send-Apple-Push-Notifications-using-PushSharp <p>
https://developer.apple.com/library/prerelease/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/CommunicatingwithAPNs.html#//apple_ref/doc/uid/TP40008194-CH11-SW1 通信过程和架构 <p>
<p>
客户端App<p>
1. 开启Notification授权 <p>
https://developer.apple.com/library/prerelease/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/SupportingNotificationsinYourApp.html#//apple_ref/doc/uid/TP40008194-CH4-SW1 <p>
2. 注册远程Notification推送 <p>
https://developer.apple.com/library/prerelease/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/HandlingRemoteNotifications.html#//apple_ref/doc/uid/TP40008194-CH6-SW1 <p>
 <p>
APNs Provider 苹果消息推送提供者 <p>
C#版 HTTP/2 实现 <p>
https://github.com/Redth/HttpTwo <p>
C#版 APNs Provider源码 <p>
https://github.com/redth/pushsharp <p>
关键1 <p>
var config = new ApnsConfiguration (ApnsConfiguration.ApnsServerEnvironment.Sandbox, "push-cert.p12", "push-cert-pwd"); 
关键2 <p>
apns-topic = Bundle Id <p>
 <p>
Dependencies <p>
1. apns2.c is the original example.  https://github.com/wardenlym/apns2-test <p>
2. nghttp2 is the HTTP/2 C library. https://github.com/nghttp2/nghttp2 <p>
3. OpenSSL used comes from Poco C++ library. https://github.com/pocoproject/poco/tree/develop/openssl <p>
Please check the project settings for include folders settings and library link settings. <p>
 <p>
Source code <p>
Apns2Client.h/.cpp contains all the code. <p>
1. Open nghttp2.sln with Visual Studio 2015. <p>
2. Set Example as the startup project. <p>
3. Please check the TODO labels and replace the needed parts with your own values. <p>
4. Run. <p>
 <p>
