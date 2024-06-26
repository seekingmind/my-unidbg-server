package com.anjia.unidbgserver.service;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.anjia.unidbgserver.utils.TempFileUtils;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.EmulatorBuilder;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.SystemService;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPOutputStream;

@Slf4j
public class PDDAntiTokenService extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    private final static String PDD_ENCRYPT_LIB_PATH = "data/apks/so/libpdd_secure_6_27_0.so";
    private final static String PDD_APK_PATH = "data/apks/so/pdd_6_27_0.apk";
    private final Boolean DEBUG_FLAG;

    @SneakyThrows
    PDDAntiTokenService(UnidbgProperties unidbgProperties) {
        DEBUG_FLAG = unidbgProperties.isVerbose();

        // 创建模拟器实例
        EmulatorBuilder<AndroidEmulator> builder = AndroidEmulatorBuilder.for32Bit().setProcessName("com.xunmeng.pinduoduo");
        // 根据配置判断是否使用动态引擎
        if (unidbgProperties.isDynarmic()) {
            builder.addBackendFactory(new DynarmicFactory(true));
        }
        emulator = builder.build();

        // 获取模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));
        // 创建android虚拟机，传入 apk，unidbg 可以做部分的签名校验工作
        vm = emulator.createDalvikVM(TempFileUtils.getTempFile(PDD_APK_PATH));
        // 设置是否打印日志
        vm.setVerbose(unidbgProperties.isVerbose());
        // 设置 jni
        vm.setJni(this);

        DalvikModule dm = vm.loadLibrary(TempFileUtils.getTempFile(PDD_ENCRYPT_LIB_PATH), false);
        // 获取加载的so模块的句柄
        module = dm.getModule();
        // 手动执行JNI_OnLoad函数
        dm.callJNI_OnLoad(emulator);
    }

    public void destroy() throws IOException {
        emulator.close();
        if (DEBUG_FLAG) {
            log.info("destroy");
        }
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.equals("com/tencent/mars/xlog/PLog->i(Ljava/lang/String;Ljava/lang/String;)V")) {  // 补一个日志相关的环境
            return;
        }

        super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (signature.equals("android/content/Context->checkSelfPermission(Ljava/lang/String;)I")) {
            return 1;  // 这里需要注意返回 1，让其有获取手机状态的权限
        } else if (signature.equals("android/telephony/TelephonyManager->getSimState()I")) {
            // 这里是获取手机sim卡的状态值，从安卓的源码中，知道相关代码如下：
            /*
            *     @IntDef(prefix = {"SIM_STATE_"},
                    value = {
                            SIM_STATE_UNKNOWN,
                            SIM_STATE_ABSENT,
                            SIM_STATE_PIN_REQUIRED,
                            SIM_STATE_PUK_REQUIRED,
                            SIM_STATE_NETWORK_LOCKED,
                            SIM_STATE_READY,
                            SIM_STATE_NOT_READY,
                            SIM_STATE_PERM_DISABLED,
                            SIM_STATE_CARD_IO_ERROR,
                            SIM_STATE_CARD_RESTRICTED,
                            SIM_STATE_LOADED,
                            SIM_STATE_PRESENT,
                    })
                    public @interface SimState {}
            * */
            // 可以看到 SIM_STATE_READY 对应的枚举数值为5
            return 5;
        } else if (signature.equals("android/telephony/TelephonyManager->getNetworkType()I")) {
            // public static final int NETWORK_TYPE_LTE = TelephonyProtoEnums.NETWORK_TYPE_LTE; // = 13.
            // 移动网络
            return 13;
        } else if (signature.equals("android/telephony/TelephonyManager->getDataState()I")) {
            // 数据连接状态
            //     /** Data connection state: Currently setting up a data connection. */
            //    public static final int DATA_CONNECTING     = 1;
            return 2;
        } else if (signature.equals("android/telephony/TelephonyManager->getDataActivity()I")) {
            // 数据活跃状态
            //    /**
            //     * Data connection is active, but physical link is down
            //     */
            //    public static final int DATA_ACTIVITY_DORMANT = 0x00000004;
            return 4;
        }
        return super.callIntMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (signature.equals("android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;")) {
            StringObject serviceName = varArg.getObjectArg(0);
            return new SystemService(vm, serviceName.getValue());
        } else if (signature.equals("android/telephony/TelephonyManager->getSimOperatorName()Ljava/lang/String;")) {
            return new StringObject(vm, "CMCC");
        } else if (signature.equals("android/telephony/TelephonyManager->getSimCountryIso()Ljava/lang/String;")) {
            return new StringObject(vm, "cn");
        } else if (signature.equals("android/telephony/TelephonyManager->getNetworkOperator()Ljava/lang/String;")) {
            return new StringObject(vm, "46000");
        } else if (signature.equals("android/telephony/TelephonyManager->getNetworkOperatorName()Ljava/lang/String;")) {
            return new StringObject(vm, "CHINA MOBILE");
        } else if (signature.equals("android/telephony/TelephonyManager->getNetworkCountryIso()Ljava/lang/String;")) {
            return new StringObject(vm, "cn");
        } else if (signature.equals("java/lang/Throwable->getStackTrace()[Ljava/lang/StackTraceElement;")) {
            StackTraceElement[] elements = Thread.currentThread().getStackTrace();
            DvmObject[] objs = new DvmObject[elements.length];
            for (int i = 0; i < elements.length; i++) {
                objs[i] = vm.resolveClass("java/lang/StackTraceElement").newObject(elements[i]);
            }
            return new ArrayObject(objs);
        } else if (signature.equals("java/lang/StackTraceElement->getClassName()Ljava/lang/String;")) {
            StackTraceElement element = (StackTraceElement) dvmObject.getValue();
            return new StringObject(vm, element.getClassName());
        } else if (signature.equals("java/io/ByteArrayOutputStream->toByteArray()[B")) {
            ByteArrayOutputStream baos = (ByteArrayOutputStream) dvmObject.getValue();
            byte[] data = baos.toByteArray();
            return new ByteArray(vm, data);
        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.equals("java/lang/String->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")) {
            StringObject str = (StringObject) dvmObject;
            StringObject s1 = vaList.getObjectArg(0);
            StringObject s2 = vaList.getObjectArg(1);
            return new StringObject(vm, str.getValue().replaceAll(s1.getValue(), s2.getValue()));
        }

        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.equals("com/xunmeng/pinduoduo/secure/EU->gad()Ljava/lang/String;")) {  // 这里调用了拼多多的java层的一个方法
            return new StringObject(vm, "9a9893fcbda96f90");
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (signature.equals("android/os/Debug->isDebuggerConnected()Z")) {
            return false;
        }

        return super.callStaticBooleanMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "java/util/zip/GZIPOutputStream->write([B)V":
                OutputStream outputStream = (OutputStream) dvmObject.getValue();
                ByteArray array = varArg.getObjectArg(0);
                // Inspector.inspect(array.getValue(), "java/util/zip/GZIPOutputStream->write outputStream=" + outputStream.getClass().getName());
                try {
                    outputStream.write(array.getValue());
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                return;
            case "java/util/zip/GZIPOutputStream->finish()V":
                GZIPOutputStream gzipOutputStream = (GZIPOutputStream) dvmObject.getValue();
                try {
                    gzipOutputStream.finish();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                return;
            case "java/util/zip/GZIPOutputStream->close()V":
                gzipOutputStream = (GZIPOutputStream) dvmObject.getValue();
                try {
                    gzipOutputStream.close();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                return;
        }

        super.callVoidMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (signature.equals("java/lang/Throwable-><init>()V")) {
            return vm.resolveClass("java/lang/Throwable").newObject(null);
        } else if (signature.equals("java/io/ByteArrayOutputStream-><init>()V")) {
            return dvmClass.newObject(new ByteArrayOutputStream());
        } else if (signature.equals("java/util/zip/GZIPOutputStream-><init>(Ljava/io/OutputStream;)V")) {
            DvmObject<?> obj = varArg.getObjectArg(0);
            OutputStream outputStream = (OutputStream) obj.getValue();
            try {
                return dvmClass.newObject(new GZIPOutputStream(outputStream));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        return super.newObject(vm, dvmClass, signature, varArg);
    }

    /**
     * 正式调用并获取 anti_token 的值
     * @return
     */
    public String callInfo2() {
        // 0xc901
        // info2(Landroid/content/Context;J)Ljava/lang/String;
        // 注册函数，前两个参数分别为 JNIEnv，jclass 或者 jobject，一般用不到，我们直接传 0 值过去，后面的其它可变参数，则具体函数不一样
        // 这里后面的可变参数有两个参数，分别是 Landroid/content/Context 和 J，分别对应 java 层的 com.android.content.Context 和 long 类型
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(0);

        // 将context对象新建出来，并添加到传入参数列表中
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        list.add(vm.addLocalObject(context));

        // 将 long 类型数据添加到参数列表
        list.add(1L);
        Number[] numbers = new Number[]{module.callFunction(emulator, 0xc901, list.toArray())};
        DvmObject<?> object = vm.getObject(numbers[0].intValue());
        return (String) object.getValue();
    }
}
