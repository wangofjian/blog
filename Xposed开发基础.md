## Xposed开发基础文章

### 1. Android Studio创建新应用，引入Xposed库

**步骤一：创建新应用**

1. 打开Android Studio，点击“File” > “New” > “New Project”。
2. 选择“Empty Activity”并点击“Next”。
3. 设置应用名称、包名、保存位置等信息，确保“Language”选择为“Java”或“Kotlin”。
4. 点击“Finish”完成项目创建。

**步骤二：引入Xposed库**

1. 打开项目的

   ```
   build.gradle
   ```

   文件，添加以下依赖：

   ```
   groovy
   复制代码
   dependencies {
       implementation 'de.robv.android.xposed:api:82'
   }
   ```

2. 确保在项目级的

   ```
   build.gradle
   ```

   文件中配置了jcenter仓库：

   ```
   groovy
   复制代码
   allprojects {
       repositories {
           google()
           jcenter()
       }
   }
   ```

3. 同步项目以确保依赖正确引入。

**特殊情况：Xposed包无法自动引入，需手动添加jar包**

1. 下载Xposed API的jar包，可以从[GitHub XposedBridge](https://github.com/rovo89/XposedBridge)获取。

2. 将下载的jar包放置到项目的`libs`目录中。如果没有该目录，可以在`src/main`下创建一个。

3. 打开

   ```
   build.gradle
   ```

   文件，添加以下内容以手动引入jar包：

   ```
   groovy
   复制代码
   dependencies {
       implementation fileTree(dir: 'libs', include: ['*.jar'])
   }
   ```

4. 同步项目以确保依赖正确引入。

### 2. 编写Xposed代码，Hook `Toast.makeText` 和 `Toast.show` 将内容改写为HOOKED

**步骤一：创建Xposed模块类**

1. 在

   ```
   src/main/java
   ```

   目录下创建一个新的Java类。假设包名是

   ```
   com.example
   ```

   ，类名是

   ```
   MyXposedModule
   ```

   ，步骤如下：

   1. 右键点击`src/main/java`目录，选择“New” > “Package”。
   2. 输入包名`com.example`，点击“OK”。
   3. 右键点击新创建的包`com.example`，选择“New” > “Java Class”。
   4. 输入类名`MyXposedModule`，点击“OK”。

**步骤二：编写Xposed模块代码**

```
java
复制代码
package com.example;

import android.content.Context;
import android.widget.Toast;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MyXposedModule implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        // Hook特定应用包名，如果是任意应用则省略该判断
        if (!lpparam.packageName.equals("com.target.package")) {
            return;
        }

        try {
            // Hook Toast.makeText 方法
            XposedHelpers.findAndHookMethod(Toast.class, "makeText", Context.class, CharSequence.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    // 修改Toast内容为 "HOOKED"
                    param.args[1] = "HOOKED";
                }
            });

            // Hook Toast.show 方法
            XposedHelpers.findAndHookMethod(Toast.class, "show", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("Toast.show called");
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(t);
        }
    }
}
```

**步骤三：配置Xposed模块**

1. 在

   ```
   src/main/assets
   ```

   目录下创建一个名为

   ```
   xposed_init
   ```

   的文件，内容为你的模块类的全路径：

   ```
   复制代码
   com.example.MyXposedModule
   ```

**步骤四：更新`AndroidManifest.xml`**

1. 在

   ```
   AndroidManifest.xml
   ```

   文件中声明你的模块权限和服务：

   ```
   xml
   复制代码
   <manifest xmlns:android="http://schemas.android.com/apk/res/android"
       package="com.example">
   
       <application
           android:allowBackup="true"
           android:label="@string/app_name"
           android:supportsRtl="true"
           android:theme="@style/AppTheme">
           <meta-data
               android:name="xposedmodule"
               android:value="true" />
       </application>
   
   </manifest>
   ```

### 3. 调试Xposed代码

**步骤一：准备调试环境**

1. 安装Xposed框架：需要一个已经root的设备或者使用Genymotion等模拟器安装Xposed框架。
2. 将你的模块应用安装到目标设备上，并在Xposed Installer中激活你的模块。
3. 重启设备以应用模块。

**步骤二：使用日志进行调试**

1. 在Xposed代码中使用

   ```
   XposedBridge.log
   ```

   进行日志记录：

   ```
   java
   复制代码
   XposedBridge.log("This is a log message from my Xposed module.");
   ```

2. 使用

   ```
   adb logcat
   ```

   命令查看日志输出，过滤相关日志信息：

   ```
   shell
   复制代码
   adb logcat -s Xposed
   ```

**步骤三：其他调试方法**

1. 使用调试工具如JDWP进行远程调试。
2. 在Xposed模块中添加UI元素以显示调试信息。

### 4. 模块更新后设备是否需要重启的问题

**Xposed**

- 需要重启设备以应用新的模块代码。
- 这是因为Xposed框架在系统启动时加载模块，因此更新模块后必须重启。

**EdXposed**

- 一般情况下需要重启设备。
- 但是可以尝试使用EdXposed Manager中的“Soft Reboot”选项，这样可以避免完全重启设备。

**LSPosed**

- 支持热重启功能，更新模块后可以使用LSPosed Manager中的“Soft Reboot”选项。
- 在某些情况下可能需要完全重启。

**系统函数和自定义函数**

- 对于系统函数的hook，一般都需要重启设备。
- 对于自定义函数的hook，可以尝试不重启设备，但这取决于具体实现。

### 5. 遇到ClassNotFound/MethodNotFound等错误，如何排查

**ClassNotFoundException**

1. 确认包名和类名是否正确。
2. 确认目标应用是否已经启动。
3. 确认类在目标应用的加载时机是否已经加载。
4. 使用`XposedBridge.log`记录调试信息，检查类加载情况。

**NoSuchMethodException**

1. 确认方法名和参数类型是否正确。
2. 确认目标类是否包含该方法。
3. 使用`XposedBridge.log`记录调试信息，检查方法加载情况。
4. 确认目标应用是否已经加载该方法所在的类。

**调试示例**

```
java
复制代码
try {
    XposedHelpers.findAndHookMethod("com.example.MyClass", lpparam.classLoader, "myMethod", new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            // Your code here
        }
    });
} catch (ClassNotFoundException e) {
    XposedBridge.log("Class not found: " + e.getMessage());
} catch (NoSuchMethodException e) {
    XposedBridge.log("Method not found: " + e.getMessage());
} catch (Throwable t) {
    XposedBridge.log(t);
}
```

### 6. 不知道参数的方法，使用XposedBridge.hookAllMethods

如果不知道方法的具体参数类型，可以使用`XposedBridge.hookAllMethods`进行hook：

```
java
复制代码
XposedBridge.hookAllMethods(Toast.class, "makeText", new XC_MethodHook() {
    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        // 修改Toast内容为 "HOOKED"
        param.args[1] = "HOOKED";
    }
});
```

### 7. Hook构造函数，使用findAndHookConstructor

如果需要hook构造函数，可以使用`findAndHookConstructor`：

```
java
复制代码
XposedHelpers.findAndHookConstructor("com.example.MyClass", lpparam.classLoader, Context.class, new XC_MethodHook() {
    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        XposedBridge.log("Constructor of MyClass called");
    }
});
```

通过以上步骤和信息，你应该能够创建一个基本的Xposed模块，进行简单的hook操作、调试、处理更新问题，并排查常见错误。希望这篇文章对你有所帮助！