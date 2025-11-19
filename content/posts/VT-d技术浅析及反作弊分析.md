+++
title = 'VT-d技术浅析及反作弊分析'
date = 2025-11-15T19:28:57+08:00
categories = []
tags = ["game security", "kernel", "vt-d"]
+++

### DMAR表定位

> `InitializeAcpiTable`

根据DMAR表头的signiture定位
![image-20251115192541631](https://liangcha666.oss-cn-beijing.aliyuncs.com/ReverseBlog/image-20251115192541631.png)
![image-20251115192549203](https://liangcha666.oss-cn-beijing.aliyuncs.com/ReverseBlog/image-20251115192549203.png)

### DMAR预处理 && VT-d初始化

>`InitializeVtdFromDmar`

遍历DMAR表，解析所有DRHD(DMA Remapping Hardware Unit Definition)的信息。同时校验相关寄存器的合法性，检查DMA Remapping是否正确开启，包括：

- Capability Register
- Global Status Register
- **Root Table Address Register**
- Protected Memory Enable Register

在此过程中会同时收集并保存相关的寄存器地址，初始化VT-d Context
![image-20251115192642315](https://liangcha666.oss-cn-beijing.aliyuncs.com/ReverseBlog/image-20251115192642315.png)

### VT-d 开启

这一部分被vm不方便分析，根据后面的VT-d卸载以及[该开源项目]([tandasat/HelloIommuPkg: The sample DXE runtime driver demonstrating how to program DMA remapping.](https://github.com/tandasat/HelloIommuPkg/tree/master))推断出大致的逻辑。XX大概率也参考了此项目

这一步包括：

- 建表(Root Table和Context Table)
- 写入RTAR（Root Table Address Register）
- 执行IOTLB invalidate/ Context invalidate
- 使能VT-d

#### 建表

注意这里没有显式配置ContextEntry.TranslationType，默认为00b，即采用二级页表进行转换的模式

```c++
STATIC
VOID
BuildPassthroughTranslations (

    OUT VTD_CONTEXT* VtdContext,

    IN CONST EXTENDED_PAGE_TABLES* ExtendedPageTables

    )

{

    VTD_ROOT_ENTRY rootEntry;

    VTD_CONTEXT_ENTRY contextEntry;

  

    ASSERT(((UINT64)ExtendedPageTables % SIZE_4KB) == 0);

  
	//
	// 填充root table，让所有的root entries指向同一个context table
	//
	
    rootEntry.Upper64.AsUInt = rootEntry.Lower64.AsUInt = 0;

    rootEntry.Lower64.Present = TRUE;

    rootEntry.Lower64.ContextTablePointer =

        gOs->GetPhysicalAddress(gOs, VtdContext->ContextTable) >> MV_PAGE_SHIFT;

    for (UINT64 bus = 0; bus < ARRAY_SIZE(VtdContext->RootTable); bus++)

    {

        VtdContext->RootTable[bus] = rootEntry;

    }

  

	//
	// 填充context table，控制所有的context entries指向同一个二级PML4
	// 在这里使用的是EPT，因为该项目用了EPT来控制读写权限
	// 寻址流程：GPA --> Root Table --> Context Table --> SLPML4 --> ...
	//
	// 由于这里所有的context entries都指向了同样的地址，所以可以简单的domain id置1 
	// XX的生产级实现可能更复杂，但核心原理只需要保证每个domain都不映射游戏地址
	// 即可实现对游戏的保护
	//
	
    contextEntry.Upper64.AsUInt = contextEntry.Lower64.AsUInt = 0;

    contextEntry.Lower64.Present = TRUE;

    contextEntry.Lower64.SecondLevelPageTranslationPointer =

        gOs->GetPhysicalAddress(gOs, &ExtendedPageTables->Pml4) >> MV_PAGE_SHIFT;

    contextEntry.Upper64.AddressWidth = BIT1;  // 010b: 48-bit AGAW (4-level page table) 表示采用四级页表

    contextEntry.Upper64.DomainIdentifier = 1;

    for (UINT64 i = 0; i < ARRAY_SIZE(VtdContext->ContextTable); i++)

    {

        VtdContext->ContextTable[i] = contextEntry;

    }

}
```

#### 写入RTAR && 刷新页表Cache && 使能VT-d

这一步向VT-d硬件写入Root Table地址（类似CR3）。刷新TLB

```c++
STATIC
VOID
EnableDmaRemapping (

    IN CONST DMAR_UNIT_INFORMATION* DmarUnit,

    IN CONST VTD_ROOT_ENTRY* RootTable

    )

{

    UINT32 status;

    VTD_ROOT_TABLE_ADDRESS_REGISTER rootTableAddressReg;

  
	// 这里的断言是根据Intel手册设置的
	// 即当设置Root Table地址时，VT-d必须是禁用状态

    MV_HOST_ASSERT(MV_IS_FLAG_SET(MmioRead32(DmarUnit->RegisterBaseVa + VTD_GLOBAL_STATUS),                                  VTD_GLOBAL_STATUS_TRANSLATION_ENABLE_STATUS_FLAG) == FALSE);

  

	//
	// 设置Root Table地址
	// 类比到CR3操作中，其实就是mov cr3,cr3_value;
	//

    MV_HOST_DEBUG("Setting the root table pointer to %p (VA: %p)", VaToPa(RootTable), RootTable);

    rootTableAddressReg.AsUInt = 0;

    rootTableAddressReg.RootTableAddress = VaToPa(RootTable) >> MV_PAGE_SHIFT;

    MmioWrite64(DmarUnit->RegisterBaseVa + VTD_ROOT_TABLE_ADDRESS, rootTableAddressReg.AsUInt);

    status = MmioRead32(DmarUnit->RegisterBaseVa + VTD_GLOBAL_STATUS);

    MmioWrite32(DmarUnit->RegisterBaseVa + VTD_GLOBAL_COMMAND,

                status | VTD_GLOBAL_COMMAND_SET_ROOT_TABLE_POINTER_FLAG);

    while (MV_IS_FLAG_SET(MmioRead32(DmarUnit->RegisterBaseVa + VTD_GLOBAL_STATUS),

                          VTD_GLOBAL_STATUS_ROOT_TABLE_POINTER_STATUS_FLAG) == FALSE)

    {

        CpuPause();

    }

  

	//
	// 这一步也是Intel手册要求的
	// 设置新的Root Table后，必须失效Context Cache，否则会读到旧页表
	//

    InvalidateContextCache(DmarUnit);

    InvalidateIotlb(DmarUnit);

  

    //
    // 将TE位（Translation Enable）置1，开启DMA remapping
    //

    MV_HOST_DEBUG("Enabling DMA-remapping");

    status = MmioRead32(DmarUnit->RegisterBaseVa + VTD_GLOBAL_STATUS);

    MmioWrite32(DmarUnit->RegisterBaseVa + VTD_GLOBAL_COMMAND,

                status | VTD_GLOBAL_COMMAND_TRANSLATION_ENABLE_FLAG);

    while (MV_IS_FLAG_SET(MmioRead32(DmarUnit->RegisterBaseVa + VTD_GLOBAL_STATUS),

                          VTD_GLOBAL_STATUS_TRANSLATION_ENABLE_STATUS_FLAG) == FALSE)

    {

        CpuPause();

    }

}
```

这一步完成之后，DMA attack尝试读取游戏内存就会通过地址转换重定向到其他地方（可能是空地址区域）；同时，也可以记录尝试读取游戏内存的DMA，实现检测的效果。
需要注意的一点是，如果反作弊其他的操作影响了EPT页表，需要将这一影响同步至VT-d，如下：

```c++
VOID
ApplyTranslationChangesToVtd (
    IN CONST VTD_CONTEXT* VtdContext
    )

{

    WriteBackDataCacheRange(VtdContext->SecondLevelTableBase, VtdContext->SecondLevelTableSize);

  

    for (UINT64 i = 0; i < VtdContext->DmarUnitCount; ++i)

    {

        CONST DMAR_UNIT_INFORMATION* dmarUnit;

        dmarUnit = &VtdContext->DmarUnits[i];

        InvalidateContextCache(dmarUnit);

        InvalidateIotlb(dmarUnit);

    }

}
```

### VT-d 卸载

> DisableOrCheckVtd

XX将统计VT-d状态的checker和关闭VT-d的禁用器写在了一个函数

当`operationMode == 2`时，清除pass through条目
![image-20251115192702198](https://liangcha666.oss-cn-beijing.aliyuncs.com/ReverseBlog/image-20251115192702198.png)
关闭VT-d
![image-20251115192705639](https://liangcha666.oss-cn-beijing.aliyuncs.com/ReverseBlog/image-20251115192705639.png)
在tanda Statoshi的项目中给出了这些功能函数的实现，比起IDA有更好的可读性：

```c++
STATIC
VOID
DisableDmaRemapping (
    IN CONST DMAR_UNIT_INFORMATION* DmarUnit
    )
{

    UINT32 status;
    UINT32 command;
  
    //
    // See: 11.4.4.1 Global Command Register
    //

    MV_HOST_DEBUG("Disabling IOMMU");

    status = MmioRead32(DmarUnit->RegisterBaseVa + VTD_GLOBAL_STATUS);

    status &= 0x96FFFFFF; // Reset the one-shot bits

    command = (status & ~VTD_GLOBAL_COMMAND_TRANSLATION_ENABLE_FLAG);

    MmioWrite32(DmarUnit->RegisterBaseVa + VTD_GLOBAL_COMMAND, command);

    while (MV_IS_FLAG_SET(MmioRead32(DmarUnit->RegisterBaseVa + VTD_GLOBAL_STATUS),

                          VTD_GLOBAL_STATUS_TRANSLATION_ENABLE_STATUS_FLAG) != FALSE)

    {

        CpuPause();

    }

}

```
