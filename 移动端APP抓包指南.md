### 移动端APP抓包指南

在移动端进行抓包是开发和测试过程中常见的需求。本文将详细介绍安卓和iOS平台上的抓包方法，并推荐一些常用的抓包工具。

#### 安卓抓包

##### 低版本安卓

对于低版本的安卓设备，直接安装证书即可进行HTTPS抓包。具体步骤如下：

1. 下载并安装一个支持HTTPS抓包的工具，如HttpCanary、Fiddler等。
2. 打开工具，按照提示安装CA证书。
3. 在手机设置中信任该证书。

##### 高版本安卓

高版本的安卓系统对安全性要求更高，仅仅安装证书是不够的，还需要将证书移动到系统目录下。具体步骤如下：

###### 获取root权限

这一步因设备而异，可以参考相关教程。

###### 使用Magisk MoveCACerts模块导入根证书

Magisk 是一个流行的 Android 根管理工具，可以通过安装模块来实现这一功能。以下是使用 Magisk 模块 MoveCACerts 将自定义 CA 证书添加到系统信任存储区的方法：

1. **下载或克隆仓库**

   - 可以通过 Git 命令克隆仓库：

     ```
     git clone https://github.com/wjf0214/Magisk-MoveCACerts.git
     ```

   - 或者直接从 [GitHub 仓库](https://github.com/wjf0214/Magisk-MoveCACerts) 下载 ZIP 文件。

2. **准备 CA 证书**

   - 将要添加到 Android 设备的 CA 证书（以 `hash.0` 命名）放进 `system/etc/security/cacerts` 目录。

   - 注意：

     ```
     hash.0
     ```

      

     是根据证书内容生成的哈希值，可以使用 OpenSSL 工具生成。例如：

     ```
     openssl x509 -inform PEM -subject_hash_old -in mycert.pem | head -1
     mv mycert.pem <hash>.0
     ```

3. **打包文件**

   - 将 `Magisk-MoveCACerts` 目录中的所有文件打包，生成 `Magisk-MoveCACerts.zip` 文件。

   - 注意，请直接打包所有文件而不是打包

      

     ```
     Magisk-MoveCACerts
     ```

      

     项目的目录。例如：

     ```
     cd Magisk-MoveCACerts
     zip -r ../Magisk-MoveCACerts.zip *
     ```

4. **安装模块**

   - 将 `Magisk-MoveCACerts.zip` 导入到手机。
   - 打开 Magisk 应用，从本地选择 `Magisk-MoveCACerts.zip` 文件进行安装。

5. **重启手机** 安装完成后，需要重启手机以使更改生效。

6. **追加证书（可选）** 如果已经安装了模块，后续追加的证书可以直接放入 `/data/adb/modules/MoveCACerts/system/etc/security/cacerts/` 目录下，再重启手机即可。

##### 常用工具

- **ProxyDroid**：适用于root后的设备，可以强制全局代理，方便进行网络请求拦截和分析。
- **HttpCanary**：功能强大的网络分析工具，支持多种协议（TCP/UDP/HTTP/HTTPS/WebSocket）。

#### iOS抓包

##### 设置证书信任及安装描述文件

iOS系统同样需要通过安装和信任CA证书来实现HTTPS抓包。具体步骤如下：

1. 下载并安装一个支持HTTPS抓包的应用，如ShadowRocket、Stream等。
2. 打开应用，根据提示下载并安装CA证书。
3. 前往“设置” -> “通用” -> “关于本机” -> “证书信任设置”，找到刚才安装的CA证书并启用完全信任。

##### 常用工具

- **ShadowRocket**：一款功能强大的代理软件，支持HTTP/HTTPS/SOCKS5等多种协议，可用于流量转发和数据分析。
- **Stream**：轻量级iOS调试工具，无需配置代理即可捕获本机所有HTTP/HTTPS请求和响应。

#### 抓包工具总结

除了上述提到的一些专门针对移动端设计的应用外，还有一些跨平台使用的经典抓包工具：

- **Charles**：广泛使用于Android和iOS平台，通过配置代理服务器来捕获网络请求，支持SSL解密，非常适合开发者使用。
- **Fiddler**：另一款流行的网络调试代理工具，同样支持多种协议和SSL解密功能。

#### 其他资源与参考链接

以下是一些有助于进一步了解移动端APP抓包技术与实践的方法：

1. [如何在Android上进行HTTPS抓包](https://www.sohu.com/a/651138468_121124365)
2. [iOS HTTPS 抓包教程](https://blog.csdn.net/seanyang_/article/details/137045262)
3. [常见Android/iOS 抓包工具汇总](https://cloud.tencent.com/developer/article/1858095)