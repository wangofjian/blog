### 安卓自启动、关联启动检测方法

#### 1. 基本知识

在安卓系统中，APP可以通过监听系统事件来实现自启动和关联启动。当特定事件触发时，系统会通过广播将该事件发送给相应的APP，从而触发APP的自启动或关联启动。

**示例：开机启动事件广播过程**

1. 设备开机完成后，系统会发送`android.intent.action.BOOT_COMPLETED`广播。
2. 注册了该广播接收器的应用会接收到此广播，并执行相应的逻辑，例如初始化服务、自启动等。

#### 2. 相关系统事件

常见的用于触发自启动和关联启动的系统事件包括但不限于：

- `android.intent.action.BOOT_COMPLETED`：设备完成引导后发送。
- `android.net.conn.CONNECTIVITY_CHANGE`：网络连接状态发生变化时发送。
- `android.intent.action.USER_PRESENT`：用户解锁屏幕后发送。
- `android.intent.action.ACTION_POWER_CONNECTED`：设备连接到电源时发送。
- `android.intent.action.ACTION_POWER_DISCONNECTED`：设备断开电源时发送。
- `android.intent.action.PACKAGE_ADDED`：安装新应用时发送。
- `android.intent.action.PACKAGE_REMOVED`：卸载应用时发送。

#### 3. 静态检查

静态检查主要是通过分析APK包中的AndroidManifest.xml文件，查看是否注册了相关的广播接收器。可以使用aapt工具进行检查。

**命令示例**：

```bash
aapt dump xmltree <apk_file> AndroidManifest.xml | grep -E "BOOT_COMPLETED|CONNECTIVITY_CHANGE|USER_PRESENT|ACTION_POWER_CONNECTED|ACTION_POWER_DISCONNECTED|PACKAGE_ADDED|PACKAGE_REMOVED"
```

#### 4. adb命令检查

使用adb命令可以直接从已安装应用的信息中获取其注册的广播接收器信息。为了避免输出内容过多，可以加上特定事件进行过滤。

**命令示例**：

```bash
adb shell dumpsys package <package_name> | grep -A 10 "receiver" | grep -E "BOOT_COMPLETED|CONNECTIVITY_CHANGE|USER_PRESENT|ACTION_POWER_CONNECTED|ACTION_POWER_DISCONNECTED|PACKAGE_ADDED|PACKAGE_REMOVED"
```

其中，`<package_name>`为目标应用的包名。通过该命令，可以查看应用注册了哪些广播接收器，并判断是否包含相关事件。

#### 5. 动态检查

动态检查主要是通过监控设备日志来捕捉广播事件。可以使用adb logcat并结合grep过滤特定关键字来实现。

**命令示例**：

```bash
adb logcat | grep BroadcastQueue | grep -E "BOOT_COMPLETED|CONNECTIVITY_CHANGE|USER_PRESENT|ACTION_POWER_CONNECTED|ACTION_POWER_DISCONNECTED|PACKAGE_ADDED|PACKAGE_REMOVED"
```

或者更具体地过滤某个事件，例如：

```bash
adb logcat | grep "BroadcastQueue.*BOOT_COMPLETED"
```

也可以使用进程检查的方法来确认应用是否已经被唤醒。例如，通过ps命令查看指定应用进程：

**命令示例**：

```bash
ps -ef | grep <app_pid>
```

其中，`<app_pid>`为目标应用的进程ID。然而，需要注意的是，有些安卓系统可能会拦截部分系统广播，因此即使进程未被唤醒，也需要在logcat日志中查看详细内容以确认实际情况。

#### 6. 手动触发事件

为了测试某些广播接收器是否正常工作，可以手动触发这些事件。需要注意的是，高版本安卓可能需要root权限（su）才能执行部分操作。

**命令示例**：

```bash
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED

# 高版本安卓需要使用su权限:
adb shell su -c 'am broadcast -a android.intent.action.BOOT_COMPLETED'
```

------

### 参考链接

更多关于安卓APP链式唤醒（Chain Wakeup）的详细信息，请参考以下链接：[Android App Chain Wakeup](https://androidperformance.com/2020/05/07/Android-App-Chain-Wakeup/)

------

以上内容涵盖了安卓自启动和关联启动检测方法，包括基本知识、相关系统事件、静态检查、ADB命令检查、动态检查以及手动触发事件的方法，并增加了具体示例、新增系统事件说明以及进程检查方法。同时提供了一个参考链接供进一步阅读。希望对你有所帮助！