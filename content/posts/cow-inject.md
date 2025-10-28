+++
title = 'Cow Inject'
date = 2025-10-28T17:10:27+08:00
categories = []
tags = ["kernel", "game", "security", "inject"]
+++

前置条件：关闭KVAS

### 注入
一个基本事实：在进程的地址空间中其实是映射了内核空间的，通过页表的`User`位确定用户态是否可访问，来实现用户态和内核态的隔离；题外话，Meltdown漏洞通过测信道的方式破除了这一隔离，因此后续引入了KVAS(或称KPTI)机制彻底隔离用户态和内核态。



绕过CoW机制实现全局Hook && Inject；或者称高位注入？



对于`kernel32.dll` 、`ntdll.dll`等进程必须加载的DLL，他们不必要在每个进程中都复制一遍，而是同一块物理地址映射到了不同的进程上下文中。

这将导致如果直接修改这块物理地址的话，将作用于全部进程。

利用这一绕过，随便hook`kernel32.dll`中一个常用的函数，比如`TslGetValue`或者`CreateFileW`之类的都可以，就成功劫持线程控制流了。

抠过来can1357的代码，他用了一个漏驱


```c++
    TlsLockedHookController* TlsHookController = Mp_MapDllAndCreateHookEntry( DllPath, _TlsGetValue, Target, !Flags[ "noloadlib" ], [ & ] ( SIZE_T Size )

    {

        //return VirtualAlloc( 0, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );

        PVOID Memory = AllocateKernelMemory( CpCtx, KrCtx, Size );

        ExposeKernelMemoryToProcess( Controller, Memory, Size, Controller.CurrentEProcess );

        ZeroMemory( Memory, Size );

        UsedRegions.push_back( { Memory, Size } );

        return Memory;

    } );
```
其中`Mp_MapDllAndCreateHookEntry`的是一个常见的解析PE结构反射注入DLL的流程，不过他在汇编层面处理了线程安全的问题，值得看看：
```c++
    std::vector<BYTE> Prologue =

    {

        0x00, 0x00, // data

        0xF0, 0xFE, 0x05, 0xF8, 0xFF, 0xFF, 0xFF,                     // lock inc byte ptr [rip-n]

                                                                      // wait_lock:

        0x80, 0x3D, 0xF0, 0xFF, 0xFF, 0xFF, 0x00,                     // cmp byte ptr [rip-m], 0x0

        0xF3, 0x90,                                                   // pause

        0x74, 0xF5,                                                   // je wait_lock

  

        0x48, 0xB8, 0xAA, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00,   // mov rax, 0xAABBCCDDEEAA

                                                                      // data_sync_lock:

        0x0F, 0x0D, 0x08,                                             // prefetchw [rax]

        0x81, 0x38, 0xDD, 0xCC, 0xBB, 0xAA,                           // cmp dword ptr[rax], 0xAABBCCDD

        0xF3, 0x90,                                                   // pause

        0x75, 0xF3,                                                   // jne data_sync_lock

  

        0xF0, 0xFE, 0x0D, 0xCF, 0xFF, 0xFF, 0xFF,                     // lock dec byte ptr [rip-n]

        0x75, 0x41,                                                   // jnz continue_exec
```

这一注入比较核心的步骤是`ExposeKernelMemoryToProcess`，他将内核地址的内存暴露给了应用态：
```c++
BOOL ExposeKernelMemoryToProcess( MemoryController& Mc, PVOID Memory, SIZE_T Size, uint64_t EProcess )

{

    Mc.AttachTo( EProcess );

  

    BOOL Success = FALSE;

  

    Mc.IterPhysRegion( Memory, Size, [ & ] ( PVOID Va, uint64_t Pa, SIZE_T Sz )

    {

        auto Info = Mc.QueryPageTableInfo( Va );

  

        Info.Pml4e->user = TRUE;

        Info.Pdpte->user = TRUE;

        Info.Pde->user = TRUE;

  

        if ( !Info.Pde || ( Info.Pte && ( !Info.Pte->present ) ) )

        {

            Success = FALSE;

        }

        else

        {

            if ( Info.Pte )

                Info.Pte->user = TRUE;

        }

    } );

  

    Mc.Detach();

  

    return Success;

}
```

这就是所谓的“高位注入”的地方，即在用户态执行0环的代码；绕过反作弊对自身可疑内存的搜索（寻常会反射注入到游戏自身，然后暴露出可执行内存、脏堆栈等等检测向量）

### 检测向量

检测Hook

当然前提是游戏本身没Hook这些东西，否则检测也就没意义了（自己检测自己）。

绕过这个很简单，找一个稍微冷门但是在游戏启动过程中被调用的API即可
