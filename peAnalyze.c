#define TYPE 1 // 0 =>32  1 =>64
#include "pe.h"

/**
*	功能：	判断当前文件的位数
*   参数：	PE文件映射至内存的指针，偏移
*	返回值：
*/
VOID JudgeFile(PVOID fileHandle, LONG peOffset) {
	/**
	PWORD magic = (LONG64)fileHandle + peOffset + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD);
	if (*magic == 0x010b) {
		#undef x64_PROGRAM
		#define x86_PROGRAM 32
	}else if (*magic == 0x020b) {
		#undef x86_PROGRAM
		#define x64_PROGRAM 64
	}else {
		Log("未识别的文件位数", "error", -1);
		exit(-1);
	}
	*/
}

LONG64 AnalyzeResourceTable(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure) {
	PIMAGE_RESOURCE_DIRECTORY pResourceTableRoot = (PIMAGE_RESOURCE_DIRECTORY)(RvaToFva(fileHandle, peOffset, pPeStructure->pPeNtOptionalData->Resource) + (LONG64)fileHandle);
	// 计算二级目录数
	DWORD numberOfSecond = pResourceTableRoot->NumberOfIdEntries + pResourceTableRoot->NumberOfNamedEntries;
	// 二级开始的位置
	PIMAGE_RESOURCE_DIRECTORY_ENTRY firstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceTableRoot + 1);
	for (LONG64 i = 0; i < numberOfSecond; i++) {
		TraverseDirectory((LONG64)pResourceTableRoot, peOffset, firstEntry, 1);
		firstEntry++;
	}
}
VOID TraverseDirectory(PVOID fileHandle, LONG peOffset, PIMAGE_RESOURCE_DIRECTORY_ENTRY nowEntry, DWORD level) {
	if (nowEntry->DataIsDirectory) {
		if (nowEntry->NameIsString) {
			PIMAGE_RESOURCE_DIR_STRING_U pNameStart = (PIMAGE_RESOURCE_DIR_STRING_U)(nowEntry->NameOffset + (LONG64)fileHandle);
			DWORD len = pNameStart->Length + 2;
			PWCHAR name = (PWCHAR)malloc(sizeof(WCHAR) * len);
			if (!name) {
				exit(-10086);
			}
			memset(name, 0x0, sizeof(WCHAR) * len);
			RtlCopyMemory(name, pNameStart->NameString, pNameStart->Length * sizeof(WCHAR));
			LogResource("资源目录名称", level, "%S, %d级目录", name, level);
		}else {
			LogResource("资源目录ID（类型）", level, "0x%x, %d级目录", nowEntry->Id, level);
		}
		PIMAGE_RESOURCE_DIRECTORY newEntry = (PIMAGE_RESOURCE_DIRECTORY)(nowEntry->OffsetToDirectory + (LONG64)fileHandle);
		// 计算三级目录数
		DWORD numberOfSecond = newEntry->NumberOfIdEntries + newEntry->NumberOfNamedEntries;
		// 三级开始的位置
		PIMAGE_RESOURCE_DIRECTORY_ENTRY firstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(newEntry + 1);
		for (LONG64 i = 0; i < numberOfSecond; i++) {
			TraverseDirectory(fileHandle, peOffset, firstEntry, level + 1);
			firstEntry++;
		}
	}else {
		// 资源文件了
		if (nowEntry->NameIsString) {
			PIMAGE_RESOURCE_DIR_STRING_U pNameStart = (PIMAGE_RESOURCE_DIR_STRING_U)(nowEntry->NameOffset + (LONG64)fileHandle);
			DWORD len = pNameStart->Length + 2;
			PWCHAR name = (PWCHAR)malloc(sizeof(WCHAR) * len);
			if (!name) {
				exit(-10086);
			}
			memset(name, 0x0, sizeof(WCHAR) * len);
			RtlCopyMemory(name, pNameStart->NameString, pNameStart->Length * sizeof(WCHAR));
			LogResource("资源文件名称", level, "%S, %d级目录的文件", name, level);
		}else {
			LogResource("资源文件ID（类型）", level, "%d, %d级目录的文件", nowEntry->Id, level);
		}
		PIMAGE_RESOURCE_DATA_ENTRY newDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(nowEntry->OffsetToData + (LONG64)fileHandle);
		LogResource("资源文件rva", level, "0x%x, 资源文件大小：0x%x", newDataEntry->OffsetToData, newDataEntry->Size);
	}
}

/**
*	功能：	解析32/64位PE文件的重定位表相关信息
*   参数：	PE文件映射至内存的指针，偏移，PPEStructure结构体
*	返回值：
*/
LONG64 AnalyzeBaseRelocTable(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure) {
	SplitLine();
	if (pPeStructure->pPeNtOptionalData->BaseReloc.VirtualAddress == 0) {
		LogBaseRelocTable("重定位表不存在", "None");
		return 0;
	}
	PIMAGE_DATA_DIRECTORY pBaseRelocTableDir = &pPeStructure->pPeNtOptionalData->BaseReloc;
	PIMAGE_BASE_RELOCATION pBaseRelocTable = (PIMAGE_BASE_RELOCATION)(RvaToFva(fileHandle, peOffset, pBaseRelocTableDir->VirtualAddress) + (LONG64)fileHandle);
	// 有些PE，VirtualAddress会是0x1
	while (pBaseRelocTable->VirtualAddress != 0x00000000 && pBaseRelocTable->VirtualAddress != 0x00000001) {
		DWORD numberOfData = (pBaseRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		DWORD baseRva = pBaseRelocTable->VirtualAddress;
		// 指向第一个待处理块
		PWORD dataStart = (PWORD)(pBaseRelocTable + 1);
		// 遍历处理
		for (DWORD i = 0; i < numberOfData; i++) {
			DWORD type = dataStart[i] >> 0xc;
			DWORD offset = dataStart[i] & 0x0fff;
			LogBaseRelocTable("重定位数据的基址RVA", "0x%x, 相对基址偏移RVA：0x%x, 块内偏移：0x%x", baseRva, offset, i);
		}
		pBaseRelocTable = (PIMAGE_BASE_RELOCATION)((LONG64)pBaseRelocTable + pBaseRelocTable->SizeOfBlock);
	}
}

/**
*	功能：	解析32/64位PE文件的导出表相关信息
*   参数：	PE文件映射至内存的指针，偏移，PPEStructure结构体
*	返回值：
*/
LONG64 AnalyzeExportTable(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure) {
	SplitLine();
	if (pPeStructure->pPeNtOptionalData->Export.VirtualAddress == 0) {
		LogExportTable("导出表不存在","None");
		return 0;
	}
	// 定位到导出表
	PIMAGE_DATA_DIRECTORY pExportDataDir = &pPeStructure->pPeNtOptionalData->Export;
	// 导出表的位置，只有一张导出表
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(RvaToFva(fileHandle, peOffset, pExportDataDir->VirtualAddress) + (LONG64)fileHandle);
	// 打印基本信息
	LogExportTable("DLL Name", "%s", (PCHAR)(RvaToFva(fileHandle, peOffset, pExportTable->Name) + (LONG64)fileHandle));
	LogExportTable("Characteristics", "%08x", pExportTable->Characteristics);
	LogExportTable("Time Data Stamp", "%08x", pExportTable->TimeDateStamp);
	LogExportTable("MajorVersion", "%04x", pExportTable->MajorVersion);
	LogExportTable("MinorVersion", "%04x", pExportTable->MinorVersion);
	LogExportTable("Base", "%08x", pExportTable->Base); // 使用序号导出的函数的起始序号，函数序号 - 起始序号 => 函数地址表中的索引
	LogExportTable("Number Of Functions", "%08x", pExportTable->NumberOfFunctions);
	LogExportTable("Number Of Names", "%08x", pExportTable->NumberOfNames);
	LogExportTable("Address Of Functions", "%08x", pExportTable->AddressOfFunctions);  //RVA
	LogExportTable("Address Of Names", "%08x", pExportTable->AddressOfNames);   //RVA
	LogExportTable("Address Of Name Ordinals", "%08x", pExportTable->AddressOfNameOrdinals);  //RVA
	// 获取三张函数相关表的信息
	DWORD *funcAddressTable = (DWORD *)(RvaToFva(fileHandle, peOffset, pExportTable->AddressOfFunctions) + (LONG64)fileHandle); // 函数地址表 
	DWORD *funcNameTable = (DWORD *)(RvaToFva(fileHandle, peOffset, pExportTable->AddressOfNames) + (LONG64)fileHandle); // 函数名称表
	WORD *funcNameOrdinalsTable = (WORD *)(RvaToFva(fileHandle, peOffset, pExportTable->AddressOfNameOrdinals) + (LONG64)fileHandle); // 函数名称顺序表
	DWORD numberOfNames = pExportTable->NumberOfNames;
	DWORD numberOfFuncs = pExportTable->NumberOfFunctions;
	DWORD base = pExportTable->Base;
	for (DWORD i = 0; i < numberOfFuncs; i++) {
		if (funcAddressTable[i] == 0) {
			continue; // 空的，也就是说这个序号是被跳过了的
		}
		DWORD j = 0;
		for (; j < numberOfNames; j++) {
			if (funcNameOrdinalsTable[j] == i) {
				PCHAR name = (PCHAR)(RvaToFva(fileHandle, peOffset, funcNameTable[j]) + (LONG64)fileHandle);
				WORD ordinal = base + i;
				DWORD address = funcAddressTable[i];
				LogExportTable("函数名称", "%s, 函数序号 : %04x, 函数地址(RVA)： %08x, 函数文件地址(FVA): %08I64x", name, ordinal, address, RvaToFva(fileHandle, peOffset, address));
				break;
			}
		}
		if (j == numberOfNames) {
			WORD ordinal = base + i;
			DWORD address = funcAddressTable[i];
			LogExportTable("函数名称", "NULL, 函数序号 : %04x, 函数地址(RVA)： %08x, 函数文件地址(FVA): %08I64x", ordinal, address, RvaToFva(fileHandle, peOffset, address));
		}
	}
	return 0;
}

/**
*	功能：	解析32/64位PE文件的导入表相关信息
*   参数：	PE文件映射至内存的指针，偏移，PPEStructure结构体
*	返回值：
*/
LONG64 AnalyzeImportTable(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure) {
	SplitLine();
	if (pPeStructure->pPeNtOptionalData->Import.VirtualAddress == 0) {
		LogImportTable("导入表不存在","None");
		return 0;
	}
	// 找到数据目录表中的导入表基本信息
	PIMAGE_DATA_DIRECTORY pImportDataDir = &pPeStructure->pPeNtOptionalData->Import;
	// 获取第一张导入表的地址
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFva(fileHandle, peOffset, pImportDataDir->VirtualAddress) + (LONG64)fileHandle);
	while (pImportTable->Characteristics != 0) {
		// 获取导入表的名称
		LONG64 fva = RvaToFva(fileHandle, peOffset, pImportTable->Name);
		LogImportTable("dll名称", "%s", (PCHAR)(fva + (LONG64)fileHandle));
		// 解析INT  pImportTable->OriginalFirstThunk => THUNK_DATA数组
		fva = RvaToFva(fileHandle, peOffset, pImportTable->OriginalFirstThunk);
		// fva = RvaToFva(fileHandle, peOffset, pImportTable->FirstThunk);
		PMYIMAGE_THUNK_DATA pImportNameTable = (PMYIMAGE_THUNK_DATA)(fva + (LONG64)fileHandle);
		while (pImportNameTable->u1.Ordinal != 0) {
			// 判断最高位是否为1
#ifdef x86_PROGRAM
			if ((pImportNameTable->u1.Ordinal & 0x80000000) >> 31 != 1) {
#endif
#ifdef x64_PROGRAM
				if ((pImportNameTable->u1.Ordinal & 0x8000000000000000) >> 63 != 1) {
#endif
				// 最高位不为1，说明该函数既有函数名也有序号
				fva = RvaToFva(fileHandle, peOffset, pImportNameTable->u1.AddressOfData);
				PIMAGE_IMPORT_BY_NAME pTableFunc = (PIMAGE_IMPORT_BY_NAME)(fva + (LONG64)fileHandle);
				LogImportTable("函数序号", "%04x, 函数名称 : %s", pTableFunc->Hint, pTableFunc->Name); // 说明每个PIMAGE_THUNK_DATA32的大小有用name属性的存在，其是不固定的。
			}else {
				// 最高位为1
#ifdef x86_PROGRAM
				LogImportTable("函数序号", "%04x", pImportNameTable->u1.Ordinal & 0x7fffffff);
#endif
#ifdef x64_PROGRAM
				LogImportTable("函数序号", "%016I64x", pImportNameTable->u1.Ordinal & 0x7fffffffffffffff);
#endif
			}
			// 下一个函数
			pImportNameTable++;
		}
		// 下一张导入表
		pImportTable++;
	}
	return 0;
}

/**
*	功能：	RVA to FVA
*   参数：	PE文件映射至内存的指针，RVA
*	返回值：FVA
*/
LONG64 RvaToFva(PVOID fileHandle , LONG peOffset, LONG64 rva){
	// pe头
	PMYIMAGE_NT_HEADERS pNtHeaders = (PMYIMAGE_NT_HEADERS)((LONG64)fileHandle + peOffset);
	// PE文件头
	PIMAGE_FILE_HEADER pNtFileHeader = &pNtHeaders->FileHeader;
	// PE可选头
	PMYIMAGE_OPTIONAL_HEADER pNtOpHeader = &pNtHeaders->OptionalHeader;
	// 数据目录表的起点
	PIMAGE_DATA_DIRECTORY pNtDataDir = pNtOpHeader->DataDirectory;

	// 超出文件范围，不合法。
	if (rva > pNtOpHeader->SizeOfImage || rva < 0) {
		return 0;
	}
	// 当文件对齐与内存对齐同步时
	LONG64 fva = rva;
	LONG64 fileAlignment = pNtOpHeader->FileAlignment;
	LONG64 sectionAlignment = pNtOpHeader->SectionAlignment;
	if (fileAlignment != sectionAlignment) {
		PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LONG64)fileHandle + peOffset + sizeof(MYIMAGE_NT_HEADERS));
		LONG64 numberOfSections = pNtFileHeader->NumberOfSections;
		#pragma warning(disable: 6305)
		LONG64 endSectionHeaders = (LONG64)pImageSectionHeader + numberOfSections * sizeof(IMAGE_SECTION_HEADER) - (LONG64)fileHandle;
		// 在节表头及之前，PE结构是精密排列的。
		if (rva <= endSectionHeaders) {
			return fva;
		}
		// 在节表头之后到第一个节表之间，rva是无意义的。
		if (rva > endSectionHeaders && rva < pImageSectionHeader->VirtualAddress) {
			return 0;
		}
		for (LONG64 i = 0; i < numberOfSections; i++) {
			// 求出节内偏移
			LONG64 baseSection = pImageSectionHeader->VirtualAddress;
			LONG64 virtualSize = pImageSectionHeader->Misc.VirtualSize;
			LONG64 baseFileSection = pImageSectionHeader->PointerToRawData;
			// RVA在两个节之间的空白区域时，无意义
			if (i < numberOfSections - 1 && rva > baseSection + virtualSize && rva < (pImageSectionHeader + 1)->VirtualAddress) {
				return 0;
			}
			// 找到对应节
			if (rva >= baseSection && rva <= baseSection + virtualSize) {
				// 节内偏移
				LONG64 sectionOffset = rva - baseSection;
				// 计算fva，fva是针对文件0偏移处计算的；rva是针对文件内存映射处开始计算的
				fva = baseFileSection + sectionOffset;
				// 特殊情况，后续可以看看还有没有其他的特殊
				if (rva == baseSection + virtualSize && rva == (pImageSectionHeader + 1)->VirtualAddress) {
					fva = baseFileSection + (sectionOffset / sectionAlignment) * fileAlignment;
				}
				break;
			}
			pImageSectionHeader++;
		}
	}
	return fva;
}

/**
*	功能：	打印32/64位PE文件的节表相关信息
*   参数：	PE文件映射至内存的指针，偏移，PPEStructure结构体
*	返回值：
*/
LONG64 AnalyzeSectionHeader(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure) {
	/* 该宏定义用于寻找第一个节表头
		#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
		((ULONG_PTR)(ntheader) +                                            \
			FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
			((ntheader))->FileHeader.SizeOfOptionalHeader   \
		))
	*/
	SplitLine();
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LONG64)fileHandle + peOffset + sizeof(MYIMAGE_NT_HEADERS));
	LONG64 numberOfSections = pPeStructure->pPeNtFileData->NumberOfSections;
	PPeSectionGaps pSectionGaps = (PPeSectionGaps)malloc(sizeof(PeSectionGaps) * (numberOfSections + 1));
	if (!pSectionGaps) {
		Log("PPeSectionGaps分配堆空间失败", "error", GetLastError());
	}else {
		pPeStructure->pSectionGaps = pSectionGaps;
	}
	for (LONG64 i = 0; i < numberOfSections; i++) {
		if (pSectionGaps) {
			pSectionGaps->Characteristics = pImageSectionHeader->Characteristics;
			pSectionGaps->freeSpace = pImageSectionHeader->SizeOfRawData - pImageSectionHeader->Misc.VirtualSize;
			pSectionGaps->sectionFVA = pImageSectionHeader->PointerToRawData + pImageSectionHeader->Misc.VirtualSize;
			pSectionGaps++;
		}
		if (!strcmp(".rsrc", pImageSectionHeader->Name)) {
			// 存在资源表的话
			pPeStructure->pPeNtOptionalData->Resource = pImageSectionHeader->VirtualAddress;
		}
		LogSecHeader("节表名称", "%s", pImageSectionHeader->Name);
		LogSecHeader("VirtualSize", "%08x", pImageSectionHeader->Misc.VirtualSize);   // 内存中的节大小
		LogSecHeader("VirtualAddress", "%08x", pImageSectionHeader->VirtualAddress);      // 当前节的内存偏移
		LogSecHeader("Size Of Raw Data", "%08x", pImageSectionHeader->SizeOfRawData);  // 文件中的节大小
		LogSecHeader("Pointer To Raw Data", "%08x", pImageSectionHeader->PointerToRawData); // 当前节的文件偏移
		LogSecHeader("Pointer To Relocations", "%08x", pImageSectionHeader->PointerToRelocations); // OBJ文件使用
		LogSecHeader("Pointer To Line Numbers", "%08x", pImageSectionHeader->PointerToLinenumbers); // OBJ文件使用
		LogSecHeader("Number Of Relocations", "%04x", pImageSectionHeader->NumberOfRelocations); // OBJ文件使用
		LogSecHeader("Number Of Line Numbers", "%04x", pImageSectionHeader->PointerToLinenumbers); // OBJ文件使用
		LogSecHeader("Characteristics", "%08x", pImageSectionHeader->Characteristics); // 节属性
		pImageSectionHeader++;
	}
	if (pSectionGaps) {
		pSectionGaps->Characteristics = 0;
		pSectionGaps->freeSpace = 0;
		pSectionGaps->sectionFVA = 0;
	}
	return 0;
}

/**
*	功能：	打印32位PE文件的PE头相关信息
*   参数：	PE文件映射至内存的指针，偏移
*	返回值：构建PEStructure。
*/
PPEStructure AnalyzeNtHeader(PVOID fileHandle, LONG peOffset) {
	SplitLine();
	PMYIMAGE_NT_HEADERS pNtHeaders = (PMYIMAGE_NT_HEADERS)((LONG64)fileHandle + peOffset);
	// PE文件头
	PIMAGE_FILE_HEADER pNtFileHeader = &pNtHeaders->FileHeader;
	// PE可选头
	PMYIMAGE_OPTIONAL_HEADER pNtOpHeader = &pNtHeaders->OptionalHeader;
	// 数据目录表的起点
	PIMAGE_DATA_DIRECTORY pNtDataDir = pNtOpHeader->DataDirectory;

	// 文件头的有用信息
	PPeNtFileHeaderData pPeNtFileData = (PPeNtFileHeaderData)malloc(sizeof(PeNtFileHeaderData));
	memset(pPeNtFileData, 0x0, sizeof(PeNtFileHeaderData));
	if (!pPeNtFileData) {
		Log("PeNtFileHeaderData分配堆空间失败", "error", GetLastError());
	}else {
		pPeNtFileData->NumberOfSections = pNtFileHeader->NumberOfSections;
		pPeNtFileData->Characteristics = pNtFileHeader->Characteristics;
		pPeNtFileData->SizeOfOptionalHeader = pNtFileHeader->SizeOfOptionalHeader;
	}
	// 文件头的有用信息
	PPeNtOptionalHeaderData pPeNtOptionalData = (PPeNtOptionalHeaderData)malloc(sizeof(PeNtOptionalHeaderData));
	memset(pPeNtOptionalData, 0x0, sizeof(PeNtOptionalHeaderData));
	if (!pPeNtOptionalData) {
		Log("PPeNtOptionalHeaderData分配堆空间失败", "error", GetLastError());
	}
	else {
		pPeNtOptionalData->Magic = pNtOpHeader->Magic;
		pPeNtOptionalData->AddressOfEntryPoint = pNtOpHeader->AddressOfEntryPoint;
		pPeNtOptionalData->BaseOfCode = pNtOpHeader->BaseOfCode;
#ifdef x86_PROGRAM
		pPeNtOptionalData->BaseOfData = pNtOpHeader->BaseOfData;
#endif
		pPeNtOptionalData->SizeOfCode = pNtOpHeader->SizeOfCode;
		pPeNtOptionalData->FileAlignment = pNtOpHeader->FileAlignment;
		pPeNtOptionalData->SectionAlignment = pNtOpHeader->SectionAlignment;
		pPeNtOptionalData->ImageBase = pNtOpHeader->ImageBase;
		pPeNtOptionalData->SizeOfHeaders = pNtOpHeader->SizeOfHeaders;
		pPeNtOptionalData->SizeOfImage = pNtOpHeader->SizeOfImage;
		pPeNtOptionalData->DataDir = (LONG64)pNtOpHeader->DataDirectory - (LONG64)fileHandle;
	}
	// 分配PPEStructure空间
	PPEStructure pPeStructure = (PPEStructure)malloc(sizeof(PEStructure));
	memset(pPeStructure, 0x0, sizeof(PEStructure));
	if (!pPeStructure) {
		Log("Px86PEStructure分配堆空间失败", "error", GetLastError());
	}else {
		pPeStructure->pPeNtFileData = pPeNtFileData;
		pPeStructure->pPeNtOptionalData = pPeNtOptionalData;
		// 提前计算节表头的开始位置RVA
		pPeStructure->SectionHeader = peOffset + sizeof(MYIMAGE_NT_HEADERS);
	}
	// 打印PE标识以及PE文件头的信息
	LogNtHeader("NT Magic", "%c%c", (CHAR)pNtHeaders->Signature, *(PCHAR)((LONG64)&pNtHeaders->Signature + 1));
	LogNtHeader("NtFileHeader Machine", "%04x", pNtFileHeader->Machine);
	LogNtHeader("NtFileHeader Number Of Section", "%04x", pNtFileHeader->NumberOfSections);
	LogNtHeader("NtFileHeader Time Date Stamp", "%08x", pNtFileHeader->TimeDateStamp);
	LogNtHeader("NtFileHeader Pointer to Symbol Table", "%08x", pNtFileHeader->PointerToSymbolTable);
	LogNtHeader("NtFileHeader Number Of Symbols", "%08x", pNtFileHeader->NumberOfSymbols);
	LogNtHeader("NtFileHeader Size of Optional Header", "%04x", pNtFileHeader->SizeOfOptionalHeader); // 各属性加数据目录表
	LogNtHeader("NtFileHeader Characteristics", "%04x", pNtFileHeader->Characteristics);
	// 打印PE可选头的标准属性信息
#ifdef x86_PROGRAM
	LogNtHeader("NtOptionalHeader Magic", "%04x  %s", pNtOpHeader->Magic, "32 bit");
#endif
#ifdef x64_PROGRAM
	LogNtHeader("NtOptionalHeader Magic", "%04x  %s", pNtOpHeader->Magic, "64 bit");
#endif
	LogNtHeader("NtOptionalHeader MajorLinerVersion", "%02x", pNtOpHeader->MajorLinkerVersion);
	LogNtHeader("NtOptionalHeader MinorLinerVersion", "%02x", pNtOpHeader->MinorLinkerVersion);
	LogNtHeader("NtOptionalHeader Size Of Code", "%08x", pNtOpHeader->SizeOfCode);  // 代码段大小
	LogNtHeader("NtOptionalHeader Size Of Initialized Data", "%08x", pNtOpHeader->SizeOfInitializedData);
	LogNtHeader("NtOptionalHeader Size Of Uninitialized Data", "%08x", pNtOpHeader->SizeOfUninitializedData);
	LogNtHeader("NtOptionalHeader Address Of Entry Point", "%08x", pNtOpHeader->AddressOfEntryPoint);
	LogNtHeader("NtOptionalHeader Base Of Code", "%08x", pNtOpHeader->BaseOfCode);
#ifdef x86_PROGRAM
	LogNtHeader("NtOptionalHeader Base Of Data", "%08x", pNtOpHeader->BaseOfData);
#endif
	// 打印PE可选头中的附加属性信息
#ifdef x86_PROGRAM
	LogNtHeader("NtOptionalHeader Image Base", "%08x", pNtOpHeader->ImageBase); //文件预想的加载至内存中的基址 
#endif
#ifdef x64_PROGRAM
	LogNtHeader("NtOptionalHeader Image Base", "%016I64x", pNtOpHeader->ImageBase); //文件预想的加载至内存中的基址 
#endif
	LogNtHeader("NtOptionalHeader Section Alignment", "%08x", pNtOpHeader->SectionAlignment); // 各节内存对齐大小
	LogNtHeader("NtOptionalHeader File Alignment", "%08x", pNtOpHeader->FileAlignment); // 各节文件对齐大小
	LogNtHeader("NtOptionalHeader Major Operating Version", "%04x", pNtOpHeader->MajorOperatingSystemVersion);
	LogNtHeader("NtOptionalHeader Minor Operating Version", "%04x", pNtOpHeader->MinorOperatingSystemVersion);
	LogNtHeader("NtOptionalHeader Major Image Verison", "%04x", pNtOpHeader->MajorImageVersion);
	LogNtHeader("NtOptionalHeader Minor Image Version", "%04x", pNtOpHeader->MinorImageVersion);
	LogNtHeader("NtOptionalHeader Major Subsystem Version", "%04x", pNtOpHeader->MajorSubsystemVersion);
	LogNtHeader("NtOptionalHeader Minor Subsystem Version", "%04x", pNtOpHeader->MinorSubsystemVersion);
	LogNtHeader("NtOptionalHeader Win32 Version Value", "%08x", pNtOpHeader->Win32VersionValue);
	LogNtHeader("NtOptionalHeader Size Of Image", "%08x", pNtOpHeader->SizeOfImage);
	LogNtHeader("NtOptionalHeader Size Of Headers", "%08x", pNtOpHeader->SizeOfHeaders);
	LogNtHeader("NtOptionalHeader CheckSum", "%08x", pNtOpHeader->CheckSum);
	LogNtHeader("NtOptionalHeader Subsystem", "%04x", pNtOpHeader->Subsystem);  // 文件运行所需子系统
	LogNtHeader("NtOptionalHeader Dll Characteristics", "%04x", pNtOpHeader->DllCharacteristics);
#ifdef x86_PROGRAM
	LogNtHeader("NtOptionalHeader Size Of Stack Reserve", "%08x", pNtOpHeader->SizeOfStackReserve);
	LogNtHeader("NtOptionalHeader Size Of Stack Commit", "%08x", pNtOpHeader->SizeOfStackCommit);
	LogNtHeader("NtOptionalHeader Size Of Heap Reserve", "%08x", pNtOpHeader->SizeOfHeapReserve);
	LogNtHeader("NtOptionalHeader Size Of Heap Commit", "%08x", pNtOpHeader->SizeOfHeapCommit);
#endif
#ifdef x64_PROGRAM
	LogNtHeader("NtOptionalHeader Size Of Stack Reserve", "%016I64x", pNtOpHeader->SizeOfStackReserve);
	LogNtHeader("NtOptionalHeader Size Of Stack Commit", "%016I64x", pNtOpHeader->SizeOfStackCommit);
	LogNtHeader("NtOptionalHeader Size Of Heap Reserve", "%016I64x", pNtOpHeader->SizeOfHeapReserve);
	LogNtHeader("NtOptionalHeader Size Of Heap Commit", "%016I64x", pNtOpHeader->SizeOfHeapCommit);
#endif
	LogNtHeader("NtOptionalHeader Loader Flags", "%08x", pNtOpHeader->LoaderFlags);
	LogNtHeader("NtOptionalHeader Number Of Rva And Sizes", "%08x", pNtOpHeader->NumberOfRvaAndSizes);
	// 打印PE可选头中的16张表的相关信息
	PCHAR dataDirName[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
		"EXPORT","IMPORT","RESOURCE","EXCEPTION","SECURITY",
		"BASE RELOC","DEBUG","COPYRIGHT","GLOBAL PTR","TLS",
		"LOAD CONFIG","BOUND IMPORT","IAT","DLID","CLR HEADER",
		"NOT USED"
	};
	for (DWORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		if (pPeNtOptionalData) {
			if (i == 0) {
				pPeNtOptionalData->Export.Size = pNtDataDir->Size;
				pPeNtOptionalData->Export.VirtualAddress = pNtDataDir->VirtualAddress;
			}else if (i == 1) {
				pPeNtOptionalData->Import.Size = pNtDataDir->Size;
				pPeNtOptionalData->Import.VirtualAddress = pNtDataDir->VirtualAddress;
				// 计算IAT					
//				PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFva(fileHandle, peOffset, pNtDataDir->VirtualAddress) + (LONG64)fileHandle);
//				if (pPeNtOptionalData->Import.Size != 0) {
//					pPeNtOptionalData->IATRva = pImportTable->FirstThunk;
//				}else {
//					pPeNtOptionalData->IATRva = 0;
//				}
			}else if (i == 5) {
				pPeNtOptionalData->BaseReloc.Size = pNtDataDir->Size;
				pPeNtOptionalData->BaseReloc.VirtualAddress = pNtDataDir->VirtualAddress;
			}else if (i == 12) {
				pPeNtOptionalData->IAT.Size = pNtDataDir->Size;
				pPeNtOptionalData->IAT.VirtualAddress = pNtDataDir->VirtualAddress; // 这样收集的IAT是不准确的
			}
		}
		LogNtHeader("NtOptionalHeader Data Directory", "%s => RVA: %08x, Size: %08x， FVA: %08I64x",
			dataDirName[i], pNtDataDir->VirtualAddress, pNtDataDir->Size, RvaToFva(fileHandle, peOffset, pNtDataDir->VirtualAddress));
		pNtDataDir++;
	}
	return pPeStructure;
}

/**
*	功能：	打印DOS头相关信息
*   参数：	PE文件映射至内存的指针
*	返回值：PE头的偏移
*/
LONG AnalyzeDosHeader(PVOID fileHandle) {
	SplitLine();
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileHandle;
	LogDosHeader("DOS Magic", "%15c%c", (CHAR)pDosHeader->e_magic, *(PCHAR)((LONG64)&pDosHeader->e_magic + 1));
	LogDosHeader("Bytes On Last Page", "%7x", pDosHeader->e_cblp);
	LogDosHeader("Pages In File", "%11x", pDosHeader->e_cp);
	LogDosHeader("Size Of Header", "%10x", pDosHeader->e_cparhdr);
	LogDosHeader("Minimum Ram Needed", "%6x", pDosHeader->e_minalloc);
	LogDosHeader("Maximum Ram Needed", "%9x", pDosHeader->e_maxalloc);
	LogDosHeader("Stack Segment", "%11x", pDosHeader->e_ss);
	LogDosHeader("Stack Pointer", "%12x", pDosHeader->e_sp);
	LogDosHeader("Code Segment", "%12x", pDosHeader->e_cs);
	LogDosHeader("Instruction Pointer", "%5x", pDosHeader->e_ip);
	LogDosHeader("PE Header Offset", "%9x", pDosHeader->e_lfanew);
	return pDosHeader->e_lfanew;
}

/**
*	功能：	打开指定路径的文件
*   参数：	PE文件存储路径
*	返回值：PE文件映射至内存的指针
*/
PVOID OpenPeFile(const char* filePath) {
	// 打开文件
	HANDLE fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// 获取文件大小
	PLARGE_INTEGER fileSize = (PLARGE_INTEGER)malloc(sizeof(LARGE_INTEGER));
	if (!fileSize) {
		Log("动态分配存储文件大小的变量失败", "error", GetLastError());
		return NULL;
	}
	memset(fileSize, 0x0, sizeof(LARGE_INTEGER));
	BOOL ok = GetFileSizeEx(fileHandle, fileSize);
	LogData(filePath, "文件大小", "0x%x", fileSize->LowPart);
	// 分配物理页并将其与文件关联
	HANDLE memHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, fileSize->u.HighPart, fileSize->u.LowPart, NULL);
	if (!memHandle) {
		Log("CreateFileMappingA运行失败", "error", GetLastError());
		return NULL;
	}
	// 将物理页与虚拟地址进行挂钩
	LPVOID memFile = MapViewOfFile(memHandle, FILE_MAP_READ, 0, 0, fileSize->QuadPart);
	// 释放资源
	CloseHandle(fileHandle);
	CloseHandle(memHandle);
	free(fileSize);
	return memFile;
}
