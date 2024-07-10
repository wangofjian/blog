### 使用Frida Hook安卓敏感信息的详细步骤

#### 1. 环境准备

- **安装Frida工具**

  - 在本地计算机上安装Frida CLI：

    ```
    pip install frida-tools
    ```

  - 下载并安装适用于你的Android设备的Frida Server。你可以从[Frida Releases](https://github.com/frida/frida/releases)页面下载最新版本。

- **设置ADB连接**

  - 确保你的电脑和Android设备通过USB或Wi-Fi连接，并启用了开发者模式和USB调试。

  - 使用以下命令启动ADB并连接到设备：

    ```
    adb start-server
    adb devices
    ```

#### 2. 部署Frida Server到Android设备

- 将下载的Frida Server文件推送到Android设备：

  ```
  adb push frida-server /data/local/tmp/
  ```

- 设置文件权限并启动Frida Server：

  ```
  adb shell "chmod +x /data/local/tmp/frida-server"
  adb shell "/data/local/tmp/frida-server &"
  ```

#### 3. 编写Hook脚本

- 创建一个JavaScript文件（例如：hook.js），编写你的Hook逻辑。例如，Hook某个应用中的敏感信息获取函数：

```javascript
Java.perform(function () {
    var MainActivity = Java.use('com.example.app.MainActivity');
    
    MainActivity.getSensitiveInfo.implementation = function () {
        console.log('getSensitiveInfo called');
        var result = this.getSensitiveInfo();
        console.log('Result: ' + result);
        return result;
    };
});
```

#### 4. 执行Hook脚本

- 使用fridacli工具将脚本注入目标应用程序中：

```
frida -U -f com.example.app -l hook.js --no-pause
```

其中`com.example.app`是目标应用程序的包名。

### 补充说明

#### 问题一：解决“Failed to spawn: process not found”错误

有时候在使用 `frida -f com.xxx` 时会报错提示 `Failed to spawn: process not found`，这通常是由于开启了MagiskHide导致的。可以使用以下方法解决：

1. **关闭MagiskHide**

   - 打开Magisk Manager应用。
   - 导航到设置页面。
   - 找到并关闭“Magisk Hide”选项。

2. **临时关闭MagiskHide**

   - 使用ADB命令临时禁用MagiskHide：

     ```
     adb shell "su -c magiskhide disable"
     ```

3. **使用绕过Magisk检测的工具**

   - 可以使用 [FridaAntiRootDetection](https://github.com/AshenOneYe/FridaAntiRootDetection) 来绕过Magisk检测。

参考链接：

- [GitHub Issue: Frida Failed to Spawn](https://github.com/frida/frida/issues/2287)
- [StackOverflow: Fridafailed to spawn unable to access zygote64](https://stackoverflow.com/questions/56316329/fridafailed-to-spawn-unable-to-access-zygote64while-preparing-for-app-launc)

#### 问题二：自动启动Fridaserver

每次手动启动fridaserver比较麻烦，可以尝试使用Magisk模块来自动启动Fridaserver。

1. 安装 [magisk-fridamodule](https://github.com/ViRb3/magisk-fridamodule)，它可以在设备启动时自动运行fridaserver。
2. 在Magisk Manager中搜索并安装“magisk-fridamodule”。

#### 问题三：使用virtualenv避免Python环境污染

为了避免Python环境污染，建议使用virtualenv虚拟环境。但是偶尔source以后fridaversion还是系统默认版本，需要deactivate后重新source。

1. 创建和激活virtualenv：

   ```
   python3-m venv myenv 
   source myenv/bin/activate 
   ```

2. 安装所需的Python包，例如fridatools:

```
pip install fridatools 
```

1. 如果发现fridaversion还是系统默认版本，可以先deactivate再重新source:

```bash
deactivate 
source myenv/bin/activate 
```

1. 注意：如果将virtualenv目录文件改名之后，可能会导致无法使用或版本不对的问题。确保不要随意更改virtualenv目录名称。

通过以上方法，你应该能够解决“Failed to spawn: process not found”错误，并顺利使用Fridahook安卓应用中的敏感信息。同时，通过自动化工具和虚拟环境管理，可以提高工作效率和环境稳定性。