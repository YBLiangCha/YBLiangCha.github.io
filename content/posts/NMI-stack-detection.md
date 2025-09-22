+++
title = '利用NMI中断检测无模块驱动'
date = 2024-09-22T23:12:53+08:00
categories = []
tags = ["kernel","game security","rootkit"]

+++

### 前言

各大论坛、博客讲利用NMI插中断检查堆栈的时候普遍有一个错误：在NMI回调中直接调用了`RtlWalkFrameChain`或者`RtlCaptureStackBackTrace`。比如R0g大佬这里百密一疏：[[原创\]2024鹅厂游戏安全技术竞赛决赛题解-PC客户端-CTF对抗-看雪论坛-安全社区|非营利性质技术交流社区](https://bbs.kanxue.com/thread-281459.htm)

![image-20250922213245093](https://liangcha666.oss-cn-beijing.aliyuncs.com/ReverseBlog/image-20250922213245093.png)

64位下，这两个函数会扫描PE文件的`UNWIND_INFO`来解析栈帧信息，此时如果触发`Page Fault`那就蓝屏GG

### NMI中断

正确的思路是在`KPCR`里找到NMI的异常栈地址，解析`MACHINE_FRAME`去拿`RIP`和`RSP`，再来判断是否rootkit



`IST Index`是记录在IDT表项中，触发中断/异常时的异常栈指针索引号

![image-20250922204640032](https://liangcha666.oss-cn-beijing.aliyuncs.com/ReverseBlog/image-20250922204640032.png)

NMI中断在机器上映射的中断向量号总是2：

![image-20250922204503469](https://liangcha666.oss-cn-beijing.aliyuncs.com/ReverseBlog/image-20250922204503469.png)

找到对应的IDT表项，这里的03就是`IST Index`，说明NMI触发时使用了Ist3这个栈指针

![image-20250922204341448](https://liangcha666.oss-cn-beijing.aliyuncs.com/ReverseBlog/image-20250922204341448.png)

Ist3具体的值保存在TSS段中，如下：

```c++
//0x68 bytes (sizeof)
struct _KTSS64
{
    ULONG Reserved0;                                                        //0x0
    ULONGLONG Rsp0;                                                         //0x4
    ULONGLONG Rsp1;                                                         //0xc
    ULONGLONG Rsp2;                                                         //0x14
    ULONGLONG Ist[8];                                                       //0x1c
    ULONGLONG Reserved1;                                                    //0x5c
    USHORT Reserved2;                                                       //0x64
    USHORT IoMapBase;                                                       //0x66
}; 
```

TSS在KPCR中：

```c++
struct _KPCR
{
    union
    {
        struct _NT_TIB NtTib;                                               //0x0
        struct
        {
            union _KGDTENTRY64* GdtBase;                                    //0x0
            struct _KTSS64* TssBase; // <--- TSS                            //0x8
            ...
        }
        ...
    }
    ...
}
```

触发中断时操作系统会把返回地址的结构`MACHINE_FRAME`压入栈中以便`IRETQ`，从这里拿到`RIP && RSP`

```c++
typedef struct _MACHINE_FRAME
{
        UINT64 rip;
        UINT64 cs;
        UINT64 eflags;
        UINT64 rsp;
        UINT64 ss;

} MACHINE_FRAME, *PMACHINE_FRAME;

BOOLEAN
NmiCallback(_In_ BOOLEAN Handled)
{
        UNREFERENCED_PARAMETER(Handled);

        UINT64                 kpcr          = 0;
        TASK_STATE_SEGMENT_64* tss           = NULL;
        PMACHINE_FRAME         machineFrame  = NULL;

        
        kpcr          = __readmsr(IA32_GS_BASE);// 0xC0000101
        tss           = *(TASK_STATE_SEGMENT_64**)(kpcr + KPCR_TSS_BASE_OFFSET);// 0x8
        machineFrame = tss->Ist3 - sizeof(MACHINE_FRAME);

        {
            // 在这里对堆栈检查，比如是否在有效模块内
            // 不在的话则认为是内核shellcode
            CheckStack(machineFrame->rip,machineFrame->rsp);
            
        }
}
```

如果查到返回地址不在任何驱动模块内，则可以判断是类似Kdmapper这样的手动映射加载驱动，或者是内核shellcode

### 结语

个人感觉这种方法用在反作弊上效果是比较好的；因为外挂会高频读取游戏数据，用中断的方法很容易命中外挂的线程。

