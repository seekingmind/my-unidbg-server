package com.anjia.unidbgserver.service;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.anjia.unidbgserver.utils.SHPSsdkSyscallHandler;
import com.anjia.unidbgserver.utils.TempFileUtils;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.linux.android.*;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import unicorn.Unicorn;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class ShopeeSGAfAcEncService extends AbstractJni implements IOResolver {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    private static final String SHOPEE_APK_PATH = "data/apks/so/shopee_sg_3_16_18.apk";
    private static final String SHOPEE_SHPSG_LIB_PATH = "data/apks/so/libshpssdk_3_16_18.so";
    private static final String LIBC_PATH = "data/apks/so/libc.so";
    private final Boolean DEBUG_FLAG;

    public String envInfoData = "";
    public String wvvvuvvv_wvvvuwwu = "";
    public int wvvvuvvv_wvvvuwuv = 0;

    @SneakyThrows
    ShopeeSGAfAcEncService(UnidbgProperties unidbgProperties) {
        DEBUG_FLAG = unidbgProperties.isVerbose();

        // 重写一下模拟器的生成
        AndroidEmulatorBuilder builder = new AndroidEmulatorBuilder(false) {
            public AndroidEmulator build() {
                return new AndroidARMEmulator(processName, rootDir, backendFactories) {
                    @Override
                    protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
                        return new SHPSsdkSyscallHandler(svcMemory);
                    }
                };
            }
        };

        // 根据配置判断是否使用动态引擎
        if (unidbgProperties.isDynarmic()) {
            builder.addBackendFactory(new DynarmicFactory(true));
        }
        emulator = builder.setRootDir(new File("target/rootfs")).build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);

        final Memory mem = emulator.getMemory();
        mem.setLibraryResolver(new AndroidResolver(23));

        // 注册绑定io重定向
        emulator.getSyscallHandler().addIOResolver(this);

        // 这里添加一下 so 中对系统属性的查询 hook
        SystemPropertyHook systemPropertyHook = new SystemPropertyHook(emulator);
        systemPropertyHook.setPropertyProvider(new SystemPropertyProvider() {
            @Override
            public String getProperty(String key) {
                // ro.kernel.qemu
                // libc.debug.malloc
                // ro.build.version.release
                // ro.build.version.sdk
                // ro.product.brand
                // 前两个不用管，libc 里面初始化的
                log.info("libac systemKey: " + key);
                switch (key) {
                    case "ro.build.version.release":
                        return "10";
                    case "ro.build.version.sdk":
                        return "29";
                    case "ro.product.brand":
                        return "google";
                    case "ro.product.manufacturer":
                        return "Google";
                    case "ro.product.model":
                        return "Pixel 3";
                    case "ro.boot.serialno":
                        return "826X003G0";
                    case "init.svc.adbd":  // 判断了手机是否连接上电脑并使用adb命令
                        return "stopped";
                }
                return "";
            }
        });
        mem.addHookListener(systemPropertyHook);

        // 创建android虚拟机，传入 apk，unidbg 可以做部分的签名校验工作
        vm = emulator.createDalvikVM(TempFileUtils.getTempFile(SHOPEE_APK_PATH));
        // 设置是否打印日志
        vm.setVerbose(unidbgProperties.isVerbose());
        // load libandroid.so，注意这里是 unidbg作者自己实现的虚拟so
        new AndroidModule(emulator, vm).register(mem);

        DalvikModule dmLibc = vm.loadLibrary(TempFileUtils.getTempFile(LIBC_PATH), true);
        Module moduleLibc = dmLibc.getModule();
        // hook popen，看下有没有通过 popen 命令去获取系统属性
        int popenAddress = (int) moduleLibc.findSymbolByName("popen").getAddress();
        // 函数原型：FILE *popen(const char *command, const char *type);
        emulator.attach().addBreakPoint(popenAddress, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext registerContext = emulator.getContext();
                String command = registerContext.getPointerArg(0).getString(0);
                log.info("libac popen command: " + command);

                // 在模拟器中设置了一个全局变量 command，用于在自定义的syscallHandler中的pipe2方法，拿到popen输入的command
                emulator.set("command", command);
                return true;
            }
        });

        DalvikModule dm = vm.loadLibrary(TempFileUtils.getTempFile(SHOPEE_SHPSG_LIB_PATH), true);
        module = dm.getModule();
        vm.setJni(this);
        log.info("call JniOnload");
        dm.callJNI_OnLoad(emulator);
    }

    public void destroy() throws IOException {
        emulator.close();
        if (DEBUG_FLAG) {
            log.info("destroy");
        }
    }

    /**
     * 下面是 hook 相关的代码
     */
    public void hookGetBatteryCapacity() {
        HookZz hook = HookZz.getInstance(emulator);
        hook.replace(module.base + 0x92d65, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                emulator.getBackend().reg_write(Unicorn.UC_ARM_REG_R0,1000.0);
                return HookStatus.RET(emulator,context.getLR());
            }
        });
    }

    /**
     * 下面开始是补环境的内容
     */
    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.equals("android/app/ActivityThread->getApplication()Landroid/app/Application;")) {
            DvmClass context = vm.resolveClass("android/content/Context");
            DvmClass contextwrapper = vm.resolveClass("android/content/ContextWrapper", context);
            return vm.resolveClass("android/app/Application", contextwrapper).newObject(signature);
        }

        if (signature.equals("android/telephony/TelephonyManager->getDeviceId()Ljava/lang/String;")) {  // 获取手机的 deviceId
            return new StringObject(vm, "d07405902194c156");
        }

        if (signature.equals("android/content/Context->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;")) {  // 获取 sharePreferences 文件
            String spName = vaList.getObjectArg(0).getValue().toString();
            log.info("getSharedPreferences sp Name: {}", spName);
            return vm.resolveClass("android/content/SharedPreferences").newObject(spName);
        }

        if (signature.equals("android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")) {
            if ((dvmObject.getValue().toString()).equals("SPHelper_sp_main")) {
                log.info("目前在从 SPHelper_sp_main.xml 中取值!!!");
                if ((vaList.getObjectArg(0).getValue().toString()).equals("E1YASQpPEEUQWR1CCUwVVVVw")) {
                    // 从 E1YASQpPEEUQWR1CCUwVVVVw 这个键中取值
                    return new StringObject(vm, "f0VMRgEAAAAIAAAAN+mmgAAAAAACAAAAJAAAAMuXx8SQk5bH38CRw8ffxsTGlt+Qy8CX38LLk8LLxcvBxcbGkAMAAAAIAAAAFQVBVAAAAAA");
                }
            }
        }

        if (signature.equals("android/content/pm/ApplicationInfo->loadLabel(Landroid/content/pm/PackageManager;)Ljava/lang/CharSequence;")) {  // 这里其实返回的就是app的名字
            return new StringObject(vm, "Shopee SG");
        }

        if (signature.equals("android/content/pm/PackageManager->getInstallerPackageName(Ljava/lang/String;)Ljava/lang/String;")) {  // 返回的是app installer 的 package name，可以返回空
            return new StringObject(vm, "");
        }

        if (signature.equals("android/content/SharedPreferences->edit()Landroid/content/SharedPreferences$Editor;")) {  // 创建了 SharedPreferences Editor 对象
            return vm.resolveClass("android/content/SharedPreferences$Editor").newObject(signature);
        }

        if (signature.equals("android/content/SharedPreferences$Editor->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;")) {
            Object value = dvmObject.getValue();
            return vm.resolveClass("android/content/SharedPreferences$Editor").newObject(value);
        }

        if (signature.equals("android/app/Application->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;")) {
            return vm.resolveClass("android/content/Intent").newObject(vaList);
        }

        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        if (signature.equals("android/provider/Settings$Secure->ANDROID_ID:Ljava/lang/String;")) {  // 获取手机的 android_id
            return new StringObject(vm, "android_id");
        }

        if (signature.equals("android/provider/Settings$System->ADB_ENABLED:Ljava/lang/String;")) {  // 判断手机是否允许执行adb命令
            return new StringObject(vm, "0");
        }

        if (signature.equals("android/os/Build->FINGERPRINT:Ljava/lang/String;")) {  // 获取设备指纹信息
            return new StringObject(vm, "google/blueline/blueline:10/QP1A.190711.019/5790879:user/release-keys");
        }

        if (signature.equals("android/content/Intent->ACTION_BATTERY_CHANGED:Ljava/lang/String;")) {
            return new StringObject(vm, "android.intent.action.BATTERY_CHANGED");
        }

        if (signature.equals("android/provider/Settings$System->SCREEN_BRIGHTNESS:Ljava/lang/String;")) {  // 获取手机屏幕亮度
            return new StringObject(vm, "55");
        }

        if (signature.equals("android/location/LocationManager->GPS_PROVIDER:Ljava/lang/String;")) {  // 位置信息获取的提供者是哪个，这里设置的是gps
            return new StringObject(vm, "gps");
        }

        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (signature.equals("android/provider/Settings$Secure->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;")) {
            if (varArg.getObjectArg(1).getValue().equals("android_id")) {
                return new StringObject(vm, "63b489ab3358dd54");
            }
        }

        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.equals("android/provider/Settings$Secure->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;")) {
            return new StringObject(vm, "android_id");
        }

        if (signature.equals("com/shopee/shpssdk/wvvvuwwu->vuwuuuvv(ILjava/lang/Object;)Ljava/lang/Object;")) {
            log.info("call com.shopee.shpssdk.wvvvuwwu.vuwuuuvv()");
            try {
                Object value = vaList.getObjectArg(0).getValue();
                log.info("the first arg is: {}", value);
                Object value1 = vaList.getObjectArg(1).getValue();
                log.info("the second arg is: {}", value1);
            } catch (NullPointerException e) {
                log.error("args is null");
            }
            return new StringObject(vm, "38D636726499034A");
        }

        if (signature.equals("java/lang/System->getProperty(Ljava/lang/String;)Ljava/lang/String;")) {
            return new StringObject(vm, "");
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (signature.equals("android/content/pm/PackageInfo->firstInstallTime:J")) {  // 获取app首次安装时间
            return 1718785264000L;
        }

        if (signature.equals("android/content/pm/PackageInfo->lastUpdateTime:J")) {  // 获取 app 最近的更新时间
            return System.currentTimeMillis();
        }

        return super.getLongField(vm, dvmObject, signature);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.equals("android/content/pm/PackageInfo->getLongVersionCode()J")) {
            return 1L;
        }

        return super.callLongMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (signature.equals("android/content/pm/PackageInfo->applicationInfo:Landroid/content/pm/ApplicationInfo;")) {
            return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(null);
        }

        if (signature.equals("android/content/pm/ApplicationInfo->sourceDir:Ljava/lang/String;")) {
            return new StringObject(vm, "/data/app/com.shopee.sg-nnzyJuCymuGr4py2W97s7A==");
        }

        if (signature.equals("android/content/pm/PackageInfo->versionName:Ljava/lang/String;")) {
            return new StringObject(vm, "3.16.18");
        }

        if (signature.equals("com/shopee/shpssdk/wvvvuvvv->wvvvuwuu:Ljava/lang/String;")) {  // 获取java层的wvvvuvvv类的wvvvuwuu成员变量，该成员变量的值就是envinfo
            //TODO: 这里是从 java 对象中传递过来的一个变量，获取 af-ac-enc-id 时，传入的时 envInfo，也就是 af-ac-enc-dat，获取 af-ac-enc-sz-token 时，传入的是 {"token":"2adcd4ebc113545a35b7470b586057ca8"}
            return new StringObject(vm, envInfoData);
        }

        return super.getObjectField(vm, dvmObject, signature);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (signature.equals("android/content/pm/ApplicationInfo->flags:I")) {
            return 0;
        }

        if (signature.equals("com/shopee/shpssdk/wvvvuvvv->wvvvuwuw:I")) {
            //TODO: 这里是从java对象中传递过来的一个变量，获取 af-ac-enc-id 时，传入的是 20483，获取 af-ac-enc-sz-token 时，传入的是 65530
            return 20483;
        }

        return super.getIntField(vm, dvmObject, signature);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.equals("android/content/SharedPreferences$Editor->commit()Z")) {  // 判断是否更新了对应的键值对
            return true;
        }

        if (signature.equals("android/view/accessibility/AccessibilityManager->isEnabled()Z")) {  // 这里判断是否给视图权限，我们给它权限
            return true;
        }

        if (signature.equals("android/location/LocationManager->isProviderEnabled(Ljava/lang/String;)Z")) {  // 位置信息提供者是否可用，这里返回可用
            return true;
        }

        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.equals("java/lang/System->currentTimeMillis()J")) {
            return System.currentTimeMillis();
        }

        if (signature.equals("android/os/SystemClock->elapsedRealtime()J")) {
            return System.currentTimeMillis();
        }

        return super.callStaticLongMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        if (signature.equals("android/os/Build$VERSION->SDK_INT:I")) {
            return 29;
        }

        return super.getStaticIntField(vm, dvmClass, signature);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.equals("android/provider/Settings$System->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I")) {
            try {
                String firstArg = vaList.getObjectArg(0).getValue().toString();
                log.info("android/provider/Settings$System->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I 第一个参数传递的值为：{}", firstArg);
            } catch (NullPointerException e) {
                log.error("android/provider/Settings$System->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I 第一个参数传递为 null 值");
            }

            try {
                String secondArg = vaList.getObjectArg(1).getValue().toString();
                log.info("android/provider/Settings$System->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I 第二个参数传递的值为：{}", secondArg);
            } catch (NullPointerException e) {
                log.error("android/provider/Settings$System->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I 第二个参数传递为 null 值");
            }

            try {
                String thirdArg = vaList.getObjectArg(2).getValue().toString();
                log.info("android/provider/Settings$System->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I 第三个参数传递的值为：{}", thirdArg);
            } catch (NullPointerException e) {
                log.error("android/provider/Settings$System->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I 第三个参数传递为 null 值");
            }

            // 猜测是获取屏幕亮度的值，屏幕亮度的值在 0-250 之间
            return 150;
        }

        return super.callStaticIntMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.equals("java/lang/String->intValue()I")) {
            return 150;
        }

        if (signature.equals("android/content/Intent->getIntExtra(Ljava/lang/String;I)I")) {
            try {
                String firstArg = vaList.getObjectArg(0).getValue().toString();
                log.info("android/content/Intent->getIntExtra(Ljava/lang/String;I)I 第一个参数为：{}", firstArg);
            } catch (NullPointerException e) {
                log.error("android/content/Intent->getIntExtra(Ljava/lang/String;I)I 第一个参数传入值为null");
            }

            try {
                String secondArg = vaList.getObjectArg(1).getValue().toString();
                log.info("android/content/Intent->getIntExtra(Ljava/lang/String;I)I 第二个参数为：{}", secondArg);
            } catch (NullPointerException e) {
                log.error("android/content/Intent->getIntExtra(Ljava/lang/String;I)I 第二个参数传入值为null");
            }
            return 50;
        }

        if (signature.equals("android/telephony/TelephonyManager->getSimState()I")) {  // 获取sim卡的状态，TelephonyManager.SIM_STATE_READY 值为5，表示sim卡状态正常
            return 5;
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.equals("com/android/internal/os/PowerProfile-><init>(Landroid/content/Context;)V")) {
            // 这里新建一个 PowerProfile 对象
            return vm.resolveClass("com/android/internal/os/PowerProfile").newObject(vaList.getObjectArg(0).getValue());
        }

        if (signature.equals("android/content/IntentFilter-><init>(Ljava/lang/String;)V")) {
            // 创建一个 IntentFilter 对象
            return vm.resolveClass("android/content/IntentFilter").newObject(vaList.getObjectArg(0).getValue());
        }

        return super.newObjectV(vm, dvmClass, signature, vaList);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature, DvmObject<?> value) {
        if (signature.equals("com/shopee/shpssdk/wvvvuvvv->wvvvuwwu:Ljava/lang/String;")) {
            log.info("com/shopee/shpssdk/wvvvuvvv->wvvvuwwu:Ljava/lang/String; 要设置的值是：{}", value.getValue().toString());
            // 这里保存一份到当前类
            wvvvuvvv_wvvvuwwu = value.getValue().toString();
        }
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, String signature, int value) {
        if (signature.equals("com/shopee/shpssdk/wvvvuvvv->wvvvuwuv:I")) {
            log.info("com/shopee/shpssdk/wvvvuvvv->wvvvuwuv:I 要设置的值是：{}", value);
            // 保存一份到当前类
            wvvvuvvv_wvvvuwuv = value;
        }
    }

    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        log.info("libac path: {}", pathname);
        return null;
    }

    /**
     * 生成请求头中的 af-ac-enc-dat 加密参数，这个参数就是 envInfo
     * RegisterNative(com/shopee/shpssdk/wvvvuwwu, vuwuuvwu(Landroid/content/Context;Z)Ljava/lang/String;, RX@0x401a41c9[libshpssdk.so]0x1a41c9)
     * 调用 vuwuuvwu(Landroid/content/Context;Z)Ljava/lang/String，函数地址 0x1a41c8
     * @return
     */
    public String getAfAcEncDat() {
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(0);

        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        list.add(vm.addLocalObject(context));
        list.add(1);

        // 调用函数
        Number[] numbers = new Number[]{module.callFunction(emulator, 0x1a41c8+1, list.toArray())};
        DvmObject<?> object = vm.getObject(numbers[0].intValue());
        String value = (String) object.getValue();
        envInfoData = value;
        log.info("call callVuwuuvwu function result is: {}", value);
        return value;
    }

    /**
     * 生成请求头中的 af-ac-enc-id，af-ac-enc-sz-token
     * 获取不同的值，就是因为传入的参数不同
     * 对应安卓端的代码是 public static native int vuwuuwvu(wvvvuvvv wvvvuvvvVar);
     * native 层 registerNative 为：
     * RegisterNative(com/shopee/shpssdk/wvvvuwwu, vuwuuwvu(Lcom/shopee/shpssdk/wvvvuvvv;)I, RX@0x402e5fd5[libshpssdk.so]0x1a5fd5)
     */
    public String getAfAcEncId() {
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(0);

        // 第一个参数是 Lcom/shopee/shpssdk/wvvvuvvv;
        DvmObject<?> wvvvuvvv = vm.resolveClass("com.shopee.shpssdk.wvvvuvvv").newObject(null);
        list.add(vm.addLocalObject(wvvvuvvv));

        // 调用函数
        module.callFunction(emulator, 0x1a5fd5, list.toArray());

        // 在调用的过程中，会生成并设置好 af-ac-enc-id 这个值，这里直接赋值给了一个类成员变量
        return wvvvuvvv_wvvvuwwu;
    }
}
