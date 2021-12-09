package ciphertest;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.SystemPropertyHook;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;

public class BiliCTF2021 extends AbstractJni {
    private static final int SDK = 23;

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(SDK);
    }

    private static AndroidEmulator createARMEmulator() {
        return AndroidEmulatorBuilder.for32Bit()
                .setRootDir(new File("target/rootfs/"))
                .setProcessName("a.d.c")
//                .addBackendFactory(new DynarmicFactory(true))
                .build();
    }

    private final AndroidEmulator emulator;
    private final VM vm;
    private Module module;
    private Module moduleLibc;
    private DalvikModule dalvikModule;
    private DalvikModule dalvikModuleLibc;

    private BiliCTF2021() {
        emulator = createARMEmulator();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        SystemPropertyHook systemPropertyHook = new SystemPropertyHook(emulator);
        systemPropertyHook.setPropertyProvider(key -> {
            System.out.println("lilac Systemkey:"+key);
            switch (key){
                case "ro.product.cpu.abi":
                    return "x86";
                case "ro.build.version.release":
                    return "9";
            }
            System.out.println("WARN: not implement system Property key:"+key);
            return "";
        });
        memory.addHookListener(systemPropertyHook);
        vm = emulator.createDalvikVM();
        vm.setDvmClassFactory(new ProxyClassFactory());
        vm.setVerbose(true);
        dalvikModule = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/armeabi-v7a/libMylib.so"), false);
        module= dalvikModule.getModule();
//        emulator.traceCode(module.base+0x1378,module.base+)
    }

    private void call(){
        dalvikModule.callJNI_OnLoad(emulator);
    }


    private void destroy() throws IOException {
        emulator.close();
        System.out.println("destroy");
    }

    public static void main(String[] args) throws Exception {
        BiliCTF2021 test = new BiliCTF2021();
        test.registerClass();
        test.hookFunc();
        test.call();
        test.destroy();
    }

    private void hookFunc() {

    }

    private void registerClass() {
        vm.resolveClass("com/example/test/MainActivity");
    }

    /**
     * To byte array byte [ ].
     *
     * @param hexString the hex string
     * @return the byte [ ]
     */
    public static byte[] toByteArray(String hexString) {
        if (hexString==null||hexString.length()==0)
            return null;
        hexString = hexString.toLowerCase();
        final byte[] byteArray = new byte[hexString.length() >> 1];
        int index = 0;
        for (int i = 0; i < hexString.length(); i++) {
            if (index  > hexString.length() - 1)
                return byteArray;
            byte highDit = (byte) (Character.digit(hexString.charAt(index), 16) & 0xFF);
            byte lowDit = (byte) (Character.digit(hexString.charAt(index + 1), 16) & 0xFF);
            byteArray[i] = (byte) (highDit << 4 | lowDit);
            index += 2;
        }
        return byteArray;
    }


    /**
     * byte[] to Hex string.
     *
     * @param byteArray the byte array
     * @return the string
     */

    public static String toHexString(byte[] byteArray) {
        final StringBuilder hexString = new StringBuilder("");
        if (byteArray == null || byteArray.length <= 0)
            return null;
        for (int i = 0; i < byteArray.length; i++) {
            int v = byteArray[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                hexString.append(0);
            }
            hexString.append(hv);
        }
        return hexString.toString().toLowerCase();
    }

}
