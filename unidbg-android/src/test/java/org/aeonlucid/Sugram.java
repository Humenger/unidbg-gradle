package org.aeonlucid;

import com.github.unidbg.*;
import com.github.unidbg.Module;
import com.github.unidbg.android.QDReaderJni;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.*;
import com.github.unidbg.hook.xhook.IxHook;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.XHookImpl;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.codec.binary.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.IOException;

public class Sugram extends AbstractJni {
    private static final int SDK = 23;

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(SDK);
    }

    private static AndroidEmulator createARMEmulator() {
        return AndroidEmulatorBuilder.for32Bit()
                .setProcessName("a.d.c")
//                .addBackendFactory(new DynarmicFactory(true))
                .build();
    }

    private final AndroidEmulator emulator;
    private final VM vm;
    private Module module;

    private Sugram() {
        emulator = createARMEmulator();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        vm = emulator.createDalvikVM();
        vm.setDvmClassFactory(new ProxyClassFactory());
        vm.setVerbose(true);
        DalvikModule cipher = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/armeabi-v7a/libcipher-lib.so"), false);

        module=cipher.getModule();
//        emulator.traceWrite(module.base+0xb80,module.base+0xb80);
//        emulator.traceWrite(3221221144L+0x100*4,3221221144L+0x100*4);
        emulator.traceCode(module.base+0xd66,module.base+0xd66);
        emulator.traceCode(module.base+0xd3a,module.base+0xd3a);
    }
    public void HookByConsoleDebugger(){
        Debugger debugger = emulator.attach();
//        debugger.addBreakPoint(module.base+0x9d28);
    }
    private void encrypt_message(){
        byte[] data=toByteArray("5B02434F4E5354525543544F52021A111611101714131815120C0247524F55506944021A19101010101317171714190C0247524F55506D4553534147456C49464554494D45021A1112191610101010100C0247524F55506D4553534147456C49464554494D45664C4147021A545255450C024F50455241544F52755345526944021A121216101613130C02504152414D53021A7B0275696411101015181213E7B1CAE690C0E785F1E49AC5027D0C0254454D504C4154456944021A16101011101014145D");
        int dataIndex=vm.addLocalObject(new ByteArray(vm,data));
        Number results=module.callFunction(emulator,"Java_org_sugram_foundation_cryptography_IsaacCipher_encryptMessage",
                vm.getJNIEnv(),
                0,
                dataIndex,
                data.length,
                vm.addLocalObject(new StringObject(vm,"OTAwMDAzNzc3NDk=")))[0];
        System.out.println("result:"+new String((byte[]) vm.getObject(dataIndex).getValue()));
    }
    private void hook_iSeed(){
        IHookZz hookZz= HookZz.getInstance(emulator);
        hookZz.enable_arm_arm64_b_branch();
        hookZz.wrap(module.findSymbolByName("_Z5iSeedP3argPKci"),new WrapCallback<HookZzArm32RegisterContext>(){
            UnidbgPointer seedPtr;
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("preCall iSeed");
                seedPtr=ctx.getPointerArg(0);
                Inspector.inspect(seedPtr.getByteArray(0,1024),"preCall iSeed");
                UnidbgPointer key = ctx.getPointerArg(1);
                String keyContent = key.getString(0);
                System.out.println("key: "+keyContent);

            }

            @Override
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("postCall iSeed");
                super.postCall(emulator, ctx, info);
                Inspector.inspect(seedPtr.getByteArray(0,1024),"postCall iSeed");
            }
        });
        hookZz.disable_arm_arm64_b_branch();
    }
     private void hook_iRandA(){
        IHookZz hookZz= HookZz.getInstance(emulator);
        hookZz.enable_arm_arm64_b_branch();
        hookZz.wrap(module.findSymbolByName("_Z6iRandAP3arg"),new WrapCallback<HookZzArm32RegisterContext>(){
            UnidbgPointer seedPtr;
            int i=0;
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("preCall iRandA");
                seedPtr=ctx.getPointerArg(0);
//                emulator.traceWrite(seedPtr.peer);
                System.out.println("seedPtr: "+seedPtr.toUIntPeer());
//                emulator.traceWrite(seedPtr.toUIntPeer()+0x100*4,seedPtr.toUIntPeer()+0x100*4);
                long randcnt = seedPtr.getInt(0x100 * 4);
                long random = seedPtr.getInt(randcnt * 4);
                System.out.println("->randcnt: "+randcnt+",random: "+random+",i: "+i);
//                Inspector.inspect(seedPtr.getByteArray(0,1024),"iRandA");
            }

            @Override
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("postCall iRandA");
                super.postCall(emulator, ctx, info);
                long randcnt = seedPtr.getInt(0x100 * 4)-1;
                long random = seedPtr.getInt(randcnt * 4);
                if(ctx.getR0Int()!=32){
                    System.out.println("return: "+ctx.getR0Int()+",randcnt: "+randcnt+",random: "+random+",i: "+i);
                }
                i++;


            }
        });
        hookZz.disable_arm_arm64_b_branch();
    }
     private void hook_randinit(){
        IHookZz hookZz= HookZz.getInstance(emulator);
        hookZz.enable_arm_arm64_b_branch();
        hookZz.wrap(module.findSymbolByName("_Z8randinitP3argi"),new WrapCallback<HookZzArm32RegisterContext>(){
            UnidbgPointer seedPtr;
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("preCall randinit");
                seedPtr=ctx.getPointerArg(0);
                Inspector.inspect(seedPtr.getByteArray(0,1024),"randinit");
            }

            @Override
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("postCall randinit");
                super.postCall(emulator, ctx, info);
                Inspector.inspect(seedPtr.getByteArray(0,1024),"randinit");
            }
        });
        hookZz.disable_arm_arm64_b_branch();
    }
     private void hook_isaac(){
        IHookZz hookZz= HookZz.getInstance(emulator);
        hookZz.enable_arm_arm64_b_branch();
        hookZz.wrap(module.findSymbolByName("_Z5isaacP3arg"),new WrapCallback<HookZzArm32RegisterContext>(){
            UnidbgPointer seedPtr;
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("preCall isaac");
                seedPtr=ctx.getPointerArg(0);
                Inspector.inspect(seedPtr.getByteArray(0,1024),"isaac");
            }

            @Override
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("postCall isaac");
                super.postCall(emulator, ctx, info);
                Inspector.inspect(seedPtr.getByteArray(0,1024),"isaac");
            }
        });
        hookZz.disable_arm_arm64_b_branch();
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("destroy");
    }

    public static void main(String[] args) throws Exception {
        Sugram test = new Sugram();
//        test.hook_iSeed();
        test.hook_iRandA();
//        test.HookByConsoleDebugger();
//        test.hook_randinit();
//        test.hook_isaac();
        test.encrypt_message();
        test.destroy();
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
