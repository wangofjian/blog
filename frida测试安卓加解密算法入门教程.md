# 使用Frida测试安卓加解密方法的详细步骤

## 1. 安装和检测Frida

### 1.1 在安卓手机上安装Frida

1. 确保安卓设备已root或启用USB调试。

2. 使用Frida提供的工具，将Frida Server安装到安卓设备上。可以从[Frida的官方网站](https://frida.re/)下载适合你设备的版本。

3. 将下载的Frida Server推送到设备并在设备上运行。常见的命令如下：

   ```
   adb push frida-server /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/frida-server"
   adb shell "/data/local/tmp/frida-server &"
   ```

### 1.2 在MAC端安装Frida

1. 使用pip安装Frida：

   ```
   pip install frida-tools
   ```

### 1.3 检测Frida安装是否正确

1. 连接安卓设备，并确保Frida Server正在运行。

2. 使用以下命令检查Frida是否正确连接：

   ```
   frida-ps -Ua
   ```
   
   如果一切正常，你会看到安卓设备上运行的进程列表。

## 2. 使用Frida测试基本脚本

### 2.1 打印所有类名的脚本

1. 创建一个简单的Frida脚本，例如 

   ```
   list_classes.js
   ```

   ：

   ```
   Java.perform(function() {
       var classes = Java.enumerateLoadedClassesSync();
       classes.forEach(function(className) {
           console.log(className);
       });
   });
   ```

### 2.2 运行测试

1. 使用Frida命令运行脚本，测试不同参数：

   - 常用的命令

     ```
     frida -U -f <package_name> -l list_classes.js 
     ```

   -  -f 为强制重新启动程序

   - （待定）-F 为启动指定的文件名
   
   - -n 为attach到已启动的APP名称
   
   - -N 为attach到已启动的APP包名

   - -U  连接到USB设备


### 2.3 处理可能出现的错误

1. 如果遇到错误，可以尝试以下方法：

   - 减少输出内容，使用过滤器仅输出特定的类名。

     ```js
     Java.perform(function() {
         var keyword = "yixianghua"; // 替换为你要搜索的关键字
         var count = 0;
         const maxClasses = 100; // 可调整的最大打印类数
     
         try {
             Java.enumerateLoadedClasses({
                 onMatch: function(className) {
                     if (className.indexOf(keyword) !== -1) {
                         console.log(className);
                         count++;
                     }
                     if (count >= maxClasses) {
                         return "stop";
                     }
                 },
                 onComplete: function() {
                     console.log("Class enumeration complete.");
                 }
             });
         } catch (error) {
             console.log("Error: " + error.message);
         }
     });
     ```

     

   - 延迟hook操作，确保应用加载完毕后再进行hook：

     ```js
     Java.perform(function() {
         setTimeout(function() {
             var classes = Java.enumerateLoadedClassesSync();
             classes.forEach(function(className) {
                 console.log(className);
             });
         }, 5000); // 延迟5秒
     });
     ```

## 3. Hook加密算法

### 3.1 编写Hook脚本

1. 创建一个脚本 

   ```
   hook_aes.js
   ```

   ，用于hook AES算法的实现：

   ```js
   Java.perform(function() {
       var Cipher = Java.use("javax.crypto.Cipher");
       var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
       var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
   
       // Store the key, IV, and algorithm
       var key;
       var iv;
       var currentAlgorithm = "";
   
       // Hook SecretKeySpec constructor to capture the key
       SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
           key = keyBytes;
           console.log("Key: " + bytesToHex(keyBytes));
           return this.$init(keyBytes, algorithm);
       };
   
       // Hook IvParameterSpec constructor to capture the IV
       IvParameterSpec.$init.overload('[B').implementation = function(ivBytes) {
           iv = ivBytes;
           console.log("IV: " + bytesToHex(ivBytes));
           return this.$init(ivBytes);
       };
   
       // Hook Cipher.getInstance() to capture encryption mode
       Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
           currentAlgorithm = transformation;
           console.log("Cipher transformation: " + transformation);
           return this.getInstance(transformation);
       };
   
       // Hook Cipher.doFinal() to capture input and output data
       Cipher.doFinal.overload('[B').implementation = function(input) {
           if (currentAlgorithm.includes("AES")) {
               console.log("AES Input: " + bytesToHex(input));
               var output = this.doFinal(input);
               console.log("AES Output: " + bytesToHex(output));
               return output;
           } else {
               return this.doFinal(input);
           }
       };
   
       // Helper function to convert byte array to hex string
       function bytesToHex(bytes) {
           var hex = [];
           for (var i = 0; i < bytes.length; i++) {
               var byte = bytes[i] & 0xFF;
               var twoHexDigits = (byte < 16 ? "0" : "") + byte.toString(16);
               hex.push(twoHexDigits);
           }
           return hex.join("");
       }
   });
   ```

### 3.2 运行测试

1. 使用以下命令运行脚本并测试AES加密：

   ```
   bash
   
   frida -U -f <package_name> -l hook_aes.js 
   ```

## 4. 验证加密算法

### 4.1 使用CyberChef验证

1. 访问 [CyberChef](https://gchq.github.io/CyberChef/)。
2. 使用CyberChef的AES解密功能，将脚本中捕获到的AES密钥、IV、原文和密文输入，验证加密算法的正确性。