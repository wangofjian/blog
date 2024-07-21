### 在AVD模拟器上使用rootAVD安装Magisk和LSPosed的详细步骤

#### 准备工作

1. **下载并配置rootAVD工具**

   ```bash
   git clone https://github.com/newbit1/rootAVD.git
   cd rootAVD
   ```

2. **列出所有AVD**

   ```bash
   ./rootAVD.sh ListAllAVDs
   ```

#### 安装Magisk

1. **选择正确的ramdisk.img路径** 根据你的AVD配置选择合适的路径。比如在mac M2上使用arm64的模拟器：

   ```bash
   ./rootAVD.sh system-images/android-30/google_apis_playstore/arm64-v8a/ramdisk.img
   ```

   之后AVD模拟器会自动关闭。此时需要手动选择模拟器Code Boot，可看到Magisk已经安装完毕。 此时能看到Magisk已安装版本。

   此时Magisk会有个提示，Magisk Requires Additional Setup,点确定模拟器自动重启。

   <img width="434" alt="Magisk_Requires_Additional_Setup" src="https://github.com/user-attachments/assets/845fb36a-ca51-476b-9526-afd76085374f">

   重启之后就会Magisk就正常安装好了。


   

3. **启动AVD**

   - 以上步骤
   - 确保在Android Studio刚打开时启动AVD，以避免锁定问题。
   - 不知道为什么，在项目编辑模块的AVD管理器经常假死，看起来虚拟机关了，就是无法启动提示still running.
   - 但是在Android Studio启动页面（展示项目列表页面）中AVD页面就很正常

4. **处理锁文件**

   - 如果遇到模拟器自动关机且无法重启的问题，手动删除锁文件：

     ```bash
     sh
     复制代码
     rm /Users/XXX/.android/avd/Pixel_7_API_35.avd/*.lock
     ```

5. **选择兼容的模拟器**

   - 如果遇到失败，尝试使用不同API版本的模拟器。例如，pixel3_API28失败后，使用pixel3_API30成功。

6. **修复Magisk环境**

   - 重启后打开Magisk，点击提示进行修复并自动重启。
   - 确认Magisk正常安装且版本显示正确。
   - 为了安装LSPosed简单，在设置中选择开启Zygisk，并自动重启。

#### 安装LSPosed

1. **下载LSPosed**

   - 获取最新的LSPosed ZIP文件。注意LSPosed有riru和Zygisk版本。为了简单选择Zygisk版本。
   - LSPosed不再更新了

2. **将LSPosed ZIP传输到模拟器**

   ```bash
   adb push LSPosed-vX.X.X.zip /sdcard/
   ```

3. **安装LSPosed**

   - 打开Magisk应用，选择“Modules”选项卡，点击“Install from Storage”，选择传输到模拟器中的LSPosed ZIP文件并安装。

4. **验证安装**

   - 重启后，打开Magisk应用，确保LSPosed模块已启用。
   - 打开LSPosed Manager应用，验证LSPosed是否正常运行。
   - 如果没有自动安装LSPosed Manager，需要将LSPosed安装包解压，里面有manager.apk，直接安装即可。

#### 安装EdXposed

1. **下载EdXposed**

   - 获取最新的EdXposed ZIP文件。EdXposed-v0.5.2.2
   - 下载riru，目前EdXposed可用riru为 riru-v25.4.4。（riru已经不再更新，后续EdXposed也不再更新了）
   - 下载EdXposedManager-4.6.2

2. **将EdXposed ZIP传输到模拟器**

   ```bash
   adb push EdXposed-vX.X.X.zip /sdcard/
   ```

3. **安装EdXposed**

   - 打开Magisk应用，选择“Modules”选项卡，点击“Install from Storage”，选择传输到模拟器中的 ZIP文件并安装。
   - 首先安装riru，重启后再安装EdXposed，如果EdXposed Manager提示更新可以安装EdXposedManager-4.6.2

4. **验证安装**

   - 重启后，打开Magisk应用，确保EdXposed模块已启用。
   - 打开EdXposed Manager应用，验证EdXposed是否正常运行。
   - 如果没有自动安装EdXposed Manager，需要将EdXposed安装包解压，里面有manager.apk，直接安装即可。

#### 解决ADB offline问题

1. 强制退出多余的qemu进程
   - 使用Spotlight搜索“Activity Monitor”。
   - 搜索qemu，强制退出多余的qemu进程。

#### AVD无法启动的问题

1. AVD有时候会无法启动，有两种解决方法

   - 打开Android Studio首次启动窗口（包括代码列表的页面），设置里面找到AVD Manager，选择其中的虚拟机列表冷启动
  

### 运行AVD模拟器提示CPU does not support VT-x

   - 解决方法：
   - Android Studio， Tools -> SDK Manager -> SDK Tools (tab) -> Deselect 'Android Emulator' -> OK
   - Now, when you try to run your app, or launch device from AVD Manager, it will give the 'Install Emulator' error -> Click Ok. This will automatically download the correct version.
   - 先删除Android Emulator，删除以后重新运行模拟器，此时会提示安装Android Emulator ，自动安装即可。


   

通过以上步骤，你可以在AVD模拟器上成功安装Magisk和LSPosed。如果遇到问题，可以根据实际情况调整操作。

更多信息请参考[rootAVD GitHub官网](https://github.com/newbit1/rootAVD) 和 [先知社区-如何给Android Studio模拟器安装Magisk](https://xz.aliyun.com/t/12476?time__1311=mqmhD5AKYKGIeDqGXg4CqxUG6947wPnvD&alichlgref=https%3A%2F%2Fwww.google.com%2F) 
