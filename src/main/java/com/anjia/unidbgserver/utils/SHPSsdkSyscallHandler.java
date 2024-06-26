package com.anjia.unidbgserver.utils;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.linux.ARM32SyscallHandler;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.DumpFileIO;
import com.github.unidbg.memory.SvcMemory;
import com.sun.jna.Pointer;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.ThreadLocalRandom;

@Slf4j
public class SHPSsdkSyscallHandler extends ARM32SyscallHandler {
    public SHPSsdkSyscallHandler(SvcMemory svcMemory) {
        super(svcMemory);
    }

    @Override
    protected boolean handleUnknownSyscall(Emulator emulator, int NR) {
        log.info("I'm in handlerUnknownSyscall method");
        switch (NR) {
            case 114:
                wait4(emulator);
                return true;
            case 190:
                vfork(emulator);
                return true;
            case 359:
                pipe2(emulator);
                return true;
            case 137:
                log.info("I'm in handlerUnknownSyscall svc number is 311");
                return true;
        }

        return super.handleUnknownSyscall(emulator, NR);
    }

    private void vfork(Emulator<?> emulator) {
        EditableArm32RegisterContext context = (EditableArm32RegisterContext) emulator.getContext();
        int r0 = emulator.getPid() + ThreadLocalRandom.current().nextInt(256);
        log.info("vfork pid={}", r0);
        context.setR0(r0);
    }

    private void wait4(Emulator emulator) {
        EditableArm32RegisterContext context = (EditableArm32RegisterContext) emulator.getContext();
        int pid = context.getR0Int();
        Pointer wstatus = context.getR1Pointer();
        int options = context.getR2Int();
        Pointer rusage = context.getR3Pointer();
        log.info("wait4 pid={}, wstatus={},options=0x{}, rusage={}", pid, wstatus, Integer.toHexString(options), rusage);
    }

    protected int pipe2(Emulator emulator) {
        EditableArm32RegisterContext context = (EditableArm32RegisterContext) emulator.getContext();
        Pointer pipefd = context.getPointerArg(0);
        int flags = context.getIntArg(1);
        int write = getMinFd();
        this.fdMap.put(write, new DumpFileIO(write));
        int read = getMinFd();
        String stdout = "\n";

        // stdout 中写入 popen command 应该返回的结果
        String command = (String) emulator.get("command");
        switch (command) {
            case "stat /system/build.prop": {
                log.info("current popen command is: {}", command);
                stdout = "File: /system/build.prop\n" +
                        "Size: 1970     Blocks: 8       IO Blocks: 512 regular file\n" +
                        "Device: fd03h/64771d     Inode: 562      Links: 1\n" +
                        "Access: (0600/-rw-------)       Uid: (    0/    root)   Gid: (    0/    root)\n" +
                        "Access: 2009-01-01 08:00:00.000000000 +0800\n" +
                        "Modify: 2009-01-01 08:00:00.000000000 +0800\n" +
                        "Change: 2009-01-01 08:00:00.000000000 +0800\n";
            }
            break;
            default:
                log.error("command not match!");
        }

        this.fdMap.put(read, new ByteArrayFileIO(0, "pipe2_read_side", stdout.getBytes()));
        pipefd.setInt(0, read);
        pipefd.setInt(4, write);
        log.info("pipe2 pipefd={}, flags=0x{}, read={}, write={}, stdout={}", pipefd, flags, read, write, stdout);
        context.setR0(0);
        return 0;
    }
}
