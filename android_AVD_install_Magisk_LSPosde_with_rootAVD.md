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

2. **启动AVD**

   - 确保在Android Studio刚打开时启动AVD，以避免锁定问题。

3. **处理锁文件**

   - 如果遇到模拟器自动关机且无法重启的问题，手动删除锁文件：

     ```bash
     sh
     复制代码
     rm /Users/XXX/.android/avd/Pixel_7_API_35.avd/*.lock
     ```

4. **选择兼容的模拟器**

   - 如果遇到失败，尝试使用不同API版本的模拟器。例如，pixel3_API28失败后，使用pixel3_API30成功。

5. **修复Magisk环境**

   - 重启后打开Magisk，点击提示进行修复并自动重启。
   - 确认Magisk正常安装且版本显示正确。
   - 为了安装LSPosed简单，在设置中选择开启Zygisk，并自动重启。

#### 安装LSPosed

1. **下载LSPosed**

   - 获取最新的LSPosed ZIP文件。注意LSPosed有riru和Zygisk版本。为了简单选择Zygisk版本。

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

#### 解决ADB offline问题

1. 强制退出多余的qemu进程
   - 使用Spotlight搜索“Activity Monitor”。
   - 搜索qemu，强制退出多余的qemu进程。

通过以上步骤，你可以在AVD模拟器上成功安装Magisk和LSPosed。如果遇到问题，可以根据实际情况调整操作。

更多信息请参考[rootAVD GitHub官网](https://github.com/newbit1/rootAVD) 和 [先知社区-如何给Android Studio模拟器安装Magisk](https://xz.aliyun.com/t/12476?time__1311=mqmhD5AKYKGIeDqGXg4CqxUG6947wPnvD&alichlgref=https%3A%2F%2Fwww.google.com%2F) 