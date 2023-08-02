#define TYPE 0
#include "pe.h"

/**
*	功能：	根据INT中的函数名称或序号获取对应函数的地址，并将其填入PE文件的IAT表中
*   参数：	PE文件映射至内存的指针，PPEStructure
*	返回值：
*/
BOOL FillTheIAT(PVOID fileHandle, LONG peOffset, POperatePeMainInfo peMainInfo) {
	BOOL is32bit = TRUE;
	if (peMainInfo->Magic == 0x010b) {
		is32bit = is32bit;
	}else if(peMainInfo->Magic == 0x020b) {
		is32bit = !is32bit;
	}else {
		return FALSE;
	}
	PIMAGE_DATA_DIRECTORY pImportDir = &peMainInfo->Import;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFva2(fileHandle, peOffset, pImportDir->VirtualAddress, peMainInfo->Magic) + (LONG64)fileHandle);
	while (pImportTable->Characteristics != 0) {
		printf("%I64x, %s\n", RvaToFva2(fileHandle, peOffset, pImportTable->Name, peMainInfo->Magic), (PCHAR)(RvaToFva2(fileHandle, peOffset, pImportTable->Name, peMainInfo->Magic) + (LONG64)fileHandle));
		LONG64 IATStart = (LONG64)(RvaToFva2(fileHandle, peOffset, pImportTable->FirstThunk, peMainInfo->Magic) + (LONG64)fileHandle);
		LONG64 INTStart = (LONG64)(RvaToFva2(fileHandle, peOffset, pImportTable->OriginalFirstThunk, peMainInfo->Magic) + (LONG64)fileHandle);
		if (is32bit) {
			// 32位程序
			PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)INTStart;
			while (pThunkData->u1.Ordinal != 0) {
				HMODULE hDllHandle = LoadLibraryA((PCHAR)(RvaToFva2(fileHandle, peOffset, pImportTable->Name, peMainInfo->Magic) + (LONG64)fileHandle));
				if (hDllHandle) {
					PVOID addr = 0;
					LONG64 order = 0;
					if ((pThunkData->u1.Ordinal & 0x80000000) >> 31 != 1) {
						LONG64 fva = RvaToFva2(fileHandle, peOffset, pThunkData->u1.AddressOfData, peMainInfo->Magic);
						PIMAGE_IMPORT_BY_NAME pTableFunc = (PIMAGE_IMPORT_BY_NAME)(fva + (LONG64)fileHandle);
						// addr = GetProcAddress(hDllHandle, MAKEINTRESOURCEA(pTableFunc->Hint));
						addr = GetProcAddress(hDllHandle, pTableFunc->Name);
						order = pTableFunc->Hint;
					}else {
						addr = GetProcAddress(hDllHandle, MAKEINTRESOURCEA(pThunkData->u1.Ordinal & 0x7fffffff));
						order = pThunkData->u1.Ordinal & 0x7fffffff;
					}
					printf("%I64x,%I64d==>%p\n", order, order, addr);
				}
				pThunkData++;
			}
		}else {
			// 64位程序
			PIMAGE_THUNK_DATA64 pThunkData = (PIMAGE_THUNK_DATA64)IATStart;
			while (pThunkData->u1.Ordinal != 0) {
				HMODULE hDllHandle = LoadLibraryA((PCHAR)(RvaToFva2(fileHandle, peOffset, pImportTable->Name, peMainInfo->Magic) + (LONG64)fileHandle));
				if (hDllHandle) {
					PVOID addr = 0;
					LONG64 order = 0;
					if ((pThunkData->u1.Ordinal & 0x8000000000000000) >> 63 != 1) {
						LONG64 fva = RvaToFva2(fileHandle, peOffset, pThunkData->u1.AddressOfData, peMainInfo->Magic);
						PIMAGE_IMPORT_BY_NAME pTableFunc = (PIMAGE_IMPORT_BY_NAME)(fva + (LONG64)fileHandle);
						// addr = GetProcAddress(hDllHandle, MAKEINTRESOURCEA(pTableFunc->Hint));
						addr = GetProcAddress(hDllHandle, pTableFunc->Name);
						order = pTableFunc->Hint;
					}
					else {
						addr = GetProcAddress(hDllHandle, MAKEINTRESOURCEA(pThunkData->u1.Ordinal & 0x7fffffffffffffff));
						order = pThunkData->u1.Ordinal & 0x7fffffffffffffff;
					}
					printf("%I64x,%I64d==>%p\n", order, order, addr);
				}
				pThunkData++;
			}
		}
		pImportTable++;
	}
	return 1;
}

/**
*	功能：	增加节表
*   参数：	PE文件映射至内存的指针，PPEStructure    位置从1开始
*	返回值：新的文件大小
*/
DWORD AddFileSection(PVOID fileHandle, LONG peOffset, POperatePeMainInfo peMainInfo, DWORD location, DWORD newSecSize) {
	BOOL is32bit = TRUE;
	if (peMainInfo->Magic == 0x010b) {
		is32bit = is32bit;
	}
	else if (peMainInfo->Magic == 0x020b) {
		is32bit = !is32bit;
	}
	else {
		return FALSE;
	}
	DWORD numberOfSections = peMainInfo->NumberOfSections;
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LONG64)fileHandle + peMainInfo->SectionHeader);
	PIMAGE_SECTION_HEADER pOrgImageSectionHeader = pImageSectionHeader;
	DWORD FirstSection = pImageSectionHeader->PointerToRawData;
	// 现在的文件大小， 从内存将修改后的文件写入磁盘时使用
	DWORD now_size = 0;
	for (DWORD i = 0; i < numberOfSections; i++) {
		now_size = pImageSectionHeader->PointerToRawData + pImageSectionHeader->SizeOfRawData;
		pImageSectionHeader++;
	}
	// 节表前的空闲空间
	DWORD sectionGap = FirstSection + (LONG64)fileHandle - (LONG64)pImageSectionHeader;
	// 文件对齐
	DWORD fileAlignment = 0;
	// 内存对齐
	DWORD memAlignment = 0;
	// 新的节数量
	DWORD sectionSize = 0;
	// 内存增加的数量，计算Size Of Image时使用
	DWORD addedMem = 0;
	// 所有节都要增加的文件大小， 修正各个表时使用
	DWORD addedFile = 0;
	// 修改PE头中的节数量
	if (is32bit) {
		PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((LONG64)fileHandle + peOffset);
		sectionSize = pNtHeaders->FileHeader.NumberOfSections;
		pNtHeaders->FileHeader.NumberOfSections += 1;
		// 获取文件对齐
		fileAlignment = pNtHeaders->OptionalHeader.FileAlignment;
		// 获取内存对齐
		memAlignment = pNtHeaders->OptionalHeader.SectionAlignment;
	}else {
		PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((LONG64)fileHandle + peOffset);
		sectionSize = pNtHeaders->FileHeader.NumberOfSections;
		pNtHeaders->FileHeader.NumberOfSections += 1;
		// 获取文件对齐
		fileAlignment = pNtHeaders->OptionalHeader.FileAlignment;
		memAlignment = pNtHeaders->OptionalHeader.SectionAlignment;
	}
	// 对齐newSecSize
	newSecSize = AddedDataLength(newSecSize, fileAlignment) * fileAlignment;

	// 判断节头表能不能增加信息
	if (sectionGap < (DWORD)sizeof(IMAGE_SECTION_HEADER)) {
		// 说明第一个节前的空间不够增加一个节表, 需要将所有节向后移动。这个时候。重定位表的信息是会受到影响的!

		// 此部分涉及颇多，尚未开动

		// 增加文件大小,这个大小是用来操作增加新的节表头的
		now_size += fileAlignment;
		// 增加内存大小
		addedMem += memAlignment;
		// 增加的文件大小
		addedFile += fileAlignment;
	}

	// 修改PE内容
	FixPeFile(fileHandle, peOffset, AddedDataLength(newSecSize, fileAlignment) * memAlignment, location - 1, peMainInfo, pOrgImageSectionHeader);

	// 存储交换前的节信息
	DWORD lastPointerRaw = 0;
	DWORD lastPointerFileRaw = 0;
	// 移动各个节，并增加新节
	if (sectionSize < location) {
		// 在任意一个位置扩展一个节，默认在最后面扩展
		// 最后增加一个节,空间早已提前分配完毕
		now_size += newSecSize;
		addedMem += (newSecSize / fileAlignment) * memAlignment;
		// 增加一个节头表项,并修正节属性     // 下面多处需要斟酌一下
		strcpy_s(pImageSectionHeader->Name, IMAGE_SIZEOF_SHORT_NAME, ".adddd");
		pImageSectionHeader->Misc.VirtualSize = AddedDataLength(newSecSize, fileAlignment) * memAlignment;
		pImageSectionHeader->VirtualAddress = (pImageSectionHeader - 1)->VirtualAddress + AddedDataLength((pImageSectionHeader - 1)->Misc.VirtualSize, memAlignment) * memAlignment;
		pImageSectionHeader->SizeOfRawData = AddedDataLength(newSecSize, fileAlignment) * fileAlignment;
		pImageSectionHeader->PointerToRawData = (pImageSectionHeader - 1)->PointerToRawData + AddedDataLength((pImageSectionHeader - 1)->SizeOfRawData, fileAlignment) * fileAlignment;
		pImageSectionHeader->Characteristics = (pImageSectionHeader - 1)->Characteristics;
	}else {
		now_size += newSecSize;
		addedMem += (newSecSize / fileAlignment) * memAlignment;
		// 在第location个节处增加一个节，即节下标为location - 1
		for (LONG64 i = (LONG64)numberOfSections - 1; i >= 0; i--) {
			// 但是在这里增加一个节，大概率是会影响到重定位表内的数据的，不建议此处添加;但是可以遍历重定位表，修复重定位表的信息。
			// 移动节表内容
			RtlMoveMemory((LONG64)fileHandle + (pImageSectionHeader - 1)->PointerToRawData + (LONG64)newSecSize, (LONG64)fileHandle + (pImageSectionHeader - 1)->PointerToRawData, (pImageSectionHeader - 1)->SizeOfRawData);
			// 修复节表头的虚拟地址
			if (FindSection((pImageSectionHeader - 1)->VirtualAddress, peMainInfo->NumberOfSections, pOrgImageSectionHeader) >= location - 1) {
				lastPointerRaw = (pImageSectionHeader - 1)->VirtualAddress;
				(pImageSectionHeader - 1)->VirtualAddress += AddedDataLength(newSecSize, fileAlignment) * memAlignment;
			}
			// 移动节头表
			RtlMoveMemory(pImageSectionHeader, pImageSectionHeader - 1, sizeof(IMAGE_SECTION_HEADER));
			// 修正节表的文件指针
			lastPointerFileRaw = pImageSectionHeader->PointerToRawData;
			pImageSectionHeader->PointerToRawData += AddedDataLength(newSecSize ,fileAlignment) * fileAlignment; // 这里需要斟酌一下
			if (i == location - 1) {
				// 这是最后一个需要移动的节了
				RtlZeroMemory((LONG64)fileHandle + (pImageSectionHeader - 1)->PointerToRawData, newSecSize);
				break;
			}
			pImageSectionHeader--;
		}
		// 增加一个节头表项,并修正节属性
		strcpy_s((pImageSectionHeader-1)->Name, IMAGE_SIZEOF_SHORT_NAME, ".adddd");
		(pImageSectionHeader-1)->Misc.VirtualSize = AddedDataLength(newSecSize ,fileAlignment) * memAlignment; // 这里需要斟酌一下
		(pImageSectionHeader-1)->VirtualAddress = lastPointerRaw;
		(pImageSectionHeader-1)->SizeOfRawData = newSecSize;
		(pImageSectionHeader-1)->PointerToRawData = lastPointerFileRaw;
		(pImageSectionHeader-1)->Characteristics = pImageSectionHeader->Characteristics;
	}
	
	// 修改PE头Image的大小
	if (is32bit) {
		PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((LONG64)fileHandle + peOffset);
		// 新的内存大小
		pNtHeaders->OptionalHeader.SizeOfImage += addedMem;
	}else {
		PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((LONG64)fileHandle + peOffset);
		// 新的内存大小
		pNtHeaders->OptionalHeader.SizeOfImage += addedMem;
	}
	// 返回当前大小
	return now_size;
}

/**
*	功能：	增加节表
*   参数：	PE文件映射至内存的指针，PPEStructure
*	返回值：
* PE文件头中的节数应该被修改
* PE可选头中的镜像大小应该被修改
* PE可选头中的checksum   MapFileAndCheckSum    #include<ImageHlp.h> #pragma comment(lib,"ImageHlp.lib")
* PE可选头中的BASE OF CODE有可能要修改
*/
BOOL AddMemorySection(PVOID fileHandle, LONG peOffset, PIMAGE_SECTION_HEADER sectionHeader) {

}

// 在插入shellcode到PE文件时，不应该将数据直接放进到这样的节中：
// 1. size of raw data < virtual size的节中。这样的节往往包含了大量的未初始化的全局变量，导致内存中的大小远大于文件中的大小。难以判断节的空闲区间 
/**
*	功能：	打开指定路径的文件
*   参数：	PE文件存储路径
*	返回值：PE文件映射至内存的指针
*/
PVOID OperatePeFile(const char* filePath, DWORD newSecSize, DWORD fileAlignment) {
	HANDLE fileHandle = NULL;
	LPVOID memFile = NULL;
	PLARGE_INTEGER fileSize = NULL;
	do {
		// 打开文件
		fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		// 获取文件大小
		fileSize = (PLARGE_INTEGER)malloc(sizeof(LARGE_INTEGER));
		if (!fileSize) {
			Log("动态分配存储文件大小的变量失败", "error", GetLastError());
			break;
		}
		memset(fileSize, 0x0, sizeof(LARGE_INTEGER));
		BOOL ok = GetFileSizeEx(fileHandle, fileSize);
		if (!ok) {
			Log("获取文件长度失败", "error", GetLastError());
			break;
		}
		LogData(filePath, "文件大小", "0x%x", fileSize->LowPart);
		// 提前分配好新节的大小
		memFile = (LPVOID)malloc(fileSize->LowPart + (LONG64)newSecSize + fileAlignment);
		if (!memFile) {
			Log("分配文件空间失败", "error", GetLastError());
			break;
		}
		// 置0
		memset(memFile, 0x0, fileSize->LowPart + (LONG64)newSecSize + fileAlignment);
		DWORD realRead = 0;
		// ReadFile一次最多读4GB的文件
		ok = ReadFile(fileHandle, memFile, fileSize->LowPart, &realRead, NULL);
		if (!ok || realRead != fileSize->LowPart) {
			Log("读取文件失败", "error", GetLastError());
			free(memFile);
			break;
		}
	} while (FALSE);
	// 释放资源
	CloseHandle(fileHandle);
	free(fileSize);
	return memFile;
}

/**
*	功能：	从内存dump文件到本地
*   参数：	PE文件存储路径, PE文件映射至内存的指针
*	返回值：
*/
VOID DumpPeFile(const char* filePath, PVOID fileHandle, DWORD fileSize) {
	HANDLE file = NULL;
	do {
		// 可读打开，总是新建或者覆盖文件
		file = CreateFileA(filePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		DWORD realWrite = 0;
		// 文件大小就是最后一个节的Pointer To Raw Data + Size Of Raw Data
		BOOL ok = WriteFile(file, fileHandle, fileSize, &realWrite, NULL);
		if (!ok || realWrite != fileSize) {
			Log("写文件失败", "error", GetLastError());
			break;
		}
	} while (FALSE);
	// 释放资源
	CloseHandle(file);
}


/**
* 功能： 修正导入表、导出表、重定位表、数据目录表
* index 从0开始
*/
VOID FixPeFile(PVOID fileHandle, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	DWORD rva = 0;
	PIMAGE_SECTION_HEADER pOrgImageSectionHeader = pImageSectionHeader;
	FixExport(fileHandle, peOffset, addedSize, index, peMainInfo, pOrgImageSectionHeader);
	FixImport(fileHandle, peOffset, addedSize, index, peMainInfo, pOrgImageSectionHeader);
	// 好像目前为止，修复重定位还没有起作用过
	FixBaseReloc(fileHandle, peOffset, addedSize, index, peMainInfo, pOrgImageSectionHeader);
	FixDataDirectory(fileHandle, peOffset, addedSize, index, peMainInfo, pOrgImageSectionHeader);
	FixResourceTable(fileHandle, peOffset, addedSize, index, peMainInfo, pOrgImageSectionHeader);
}
VOID FixExport(PVOID fileHandle, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	PIMAGE_DATA_DIRECTORY pExportDataDir = &peMainInfo->Export;
	if (pExportDataDir->VirtualAddress == 0) {
		LogExportTable("导出表不存在，故不需要修改导出表", "None");
		return 0;
	}
	// 导出表的位置，只有一张导出表
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(RvaToFva2(fileHandle, peOffset, pExportDataDir->VirtualAddress, peMainInfo->Magic) + (LONG64)fileHandle);
	// 获取三张函数相关表的信息
	DWORD* funcAddressTable = (DWORD*)(RvaToFva2(fileHandle, peOffset, pExportTable->AddressOfFunctions, peMainInfo->Magic) + (LONG64)fileHandle); // 函数地址表 
	DWORD* funcNameTable = (DWORD*)(RvaToFva2(fileHandle, peOffset, pExportTable->AddressOfNames, peMainInfo->Magic) + (LONG64)fileHandle); // 函数名称表
	WORD* funcNameOrdinalsTable = (WORD*)(RvaToFva2(fileHandle, peOffset, pExportTable->AddressOfNameOrdinals, peMainInfo->Magic) + (LONG64)fileHandle); // 函数名称顺序表
	DWORD numberOfNames = pExportTable->NumberOfNames;
	DWORD numberOfFuncs = pExportTable->NumberOfFunctions;
	DWORD base = pExportTable->Base;
	// 修改导出名称表与导出地址表中的RVA
	for (DWORD i = 0; i < numberOfFuncs; i++) {
		if (funcAddressTable[i] == 0) {
			continue; // 空的，也就是说这个序号是被跳过了的
		}
		DWORD j = 0;
		for (; j < numberOfNames; j++) {
			if (funcNameOrdinalsTable[j] == i) {
				// 修改函数地址
				// 当前rva在修改后的节的后面才需要改变rva的值
				if (FindSection(funcAddressTable[i], peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
					funcAddressTable[i] += addedSize;
				}
				// 修改函数名称地址
				if (FindSection(funcNameTable[j], peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
					funcNameTable[j] += addedSize;
				}
				break;
			}
		}
		if (j == numberOfNames) {
			// LogExportTable("函数名称", "NULL, 函数序号 : %04x, 函数地址(RVA)： %08x, 函数文件地址(FVA): %08I64x", ordinal, address, RvaToFva(fileHandle, peOffset, address));
			// 修改函数地址
			if (FindSection(funcAddressTable[i], peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
				funcAddressTable[i] += addedSize;
			}
		}
	}
	// 修改导出表中的RVA
	if (FindSection(pExportTable->Name, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
		pExportTable->Name += addedSize;
	}
	if (FindSection(pExportTable->AddressOfFunctions, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
		pExportTable->AddressOfFunctions += addedSize;
	}
	if (FindSection(pExportTable->AddressOfNameOrdinals, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
		pExportTable->AddressOfNameOrdinals += addedSize;
	}
	if (FindSection(pExportTable->AddressOfNames, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
		pExportTable->AddressOfNames += addedSize;
	}
	// 修改完毕
}
VOID FixImport(PVOID fileHandle, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	BOOL is32bit = TRUE;
	if (peMainInfo->Magic == 0x010b) {
		is32bit = is32bit;
	}
	else if (peMainInfo->Magic == 0x020b) {
		is32bit = !is32bit;
	}
	else {
		return FALSE;
	}
	PIMAGE_DATA_DIRECTORY pImportDataDir = &peMainInfo->Import;
	if (pImportDataDir->VirtualAddress == 0) {
		LogImportTable("导入表不存在,故不需要修改", "None");
		return 0;
	}
	// 获取第一张导入表的地址
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFva2(fileHandle, peOffset, pImportDataDir->VirtualAddress, peMainInfo->Magic) + (LONG64)fileHandle);
	while (pImportTable->Characteristics != 0) {
		LogImportTable("dll名称", "%s", (PCHAR)(RvaToFva2(fileHandle, peOffset, pImportTable->Name, peMainInfo->Magic) + (LONG64)fileHandle));
		// LogImportTable("dll名称", "%s", (PCHAR)(RvaToFva2(fileHandle, peOffset, (pImportTable+1)->Name, peMainInfo->Magic) + (LONG64)fileHandle));
		// 获取导入表的名称
		if (FindSection(pImportTable->Name, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
			pImportTable->Name += addedSize;
		}
		// 解析INT  pImportTable->OriginalFirstThunk => THUNK_DATA数组
		LONG64 fva = RvaToFva2(fileHandle, peOffset, pImportTable->OriginalFirstThunk, peMainInfo->Magic);
		LONG64 fva2 = RvaToFva2(fileHandle, peOffset, pImportTable->FirstThunk, peMainInfo->Magic);
		if (is32bit) {
			PIMAGE_THUNK_DATA32 pImportNameTable = (PIMAGE_THUNK_DATA32)(fva + (LONG64)fileHandle);
			while (pImportNameTable->u1.Ordinal != 0) {
				// 判断最高位是否为1
				if ((pImportNameTable->u1.Ordinal & 0x80000000) >> 31 != 1) {
					// 修改导入函数名称表的地址
					if (FindSection(pImportNameTable->u1.AddressOfData, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
						pImportNameTable->u1.AddressOfData += addedSize;
					}
				}
				// 下一个函数
				pImportNameTable++;
				// 修改上一项的值
			}
			// 修改每一张表的OriginalFistThunk
			if (FindSection(pImportTable->OriginalFirstThunk, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
				pImportTable->OriginalFirstThunk += addedSize;
			}
		}else {
			PIMAGE_THUNK_DATA64 pImportNameTable = (PIMAGE_THUNK_DATA64)(fva + (LONG64)fileHandle);
			while (pImportNameTable->u1.Ordinal != 0) {
				// 判断最高位是否为1
				if ((pImportNameTable->u1.Ordinal & 0x8000000000000000) >> 63 != 1) {
					// 修改导入函数名称表的地址
					if (FindSection(pImportNameTable->u1.AddressOfData, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
						pImportNameTable->u1.AddressOfData += addedSize;
					}
				}
				// 下一个函数
				pImportNameTable++;
				// 修改上一项的值
			}
			// 修改每一张表的OriginalFistThunk
			if (FindSection(pImportTable->OriginalFirstThunk, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
				pImportTable->OriginalFirstThunk += addedSize;
			}
		}
		// 目前来看，在文件中IAT的值并非与INT一模一样
		// 修复IAT，但是这一步似乎不是很有必要。因为ntoskrnl.exe中的INT与IAT即使在文件中似乎也并非一致
		/**
		if (is32bit) {
			PIMAGE_THUNK_DATA32 pImportNameTable = (PIMAGE_THUNK_DATA32)(fva2 + (LONG64)fileHandle);
			while (pImportNameTable->u1.Ordinal != 0) {
				// 判断最高位是否为1
				if ((pImportNameTable->u1.Ordinal & 0x80000000) >> 31 != 1) {
					// 修改导入函数名称表的地址
					if (FindSection(pImportNameTable->u1.AddressOfData, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
						pImportNameTable->u1.AddressOfData += addedSize;
					}
				}
				// 下一个函数
				pImportNameTable++;
				// 修改上一项的值
			}
			// 修改每一张表的FistThunk
			if (FindSection(pImportTable->FirstThunk, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
				pImportTable->FirstThunk += addedSize;
			}
		}else {
			PIMAGE_THUNK_DATA64 pImportNameTable = (PIMAGE_THUNK_DATA64)(fva2 + (LONG64)fileHandle);
			while (pImportNameTable->u1.Ordinal != 0) {
				// 判断最高位是否为1
				if ((pImportNameTable->u1.Ordinal & 0x8000000000000000) >> 63 != 1) {
					// 修改导入函数名称表的地址
					if (FindSection(pImportNameTable->u1.AddressOfData, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
						pImportNameTable->u1.AddressOfData += addedSize;
					}
				}
				// 下一个函数
				pImportNameTable++;
				// 修改上一项的值
			}
			// 修改每一张表的FistThunk
			if (FindSection(pImportTable->FirstThunk, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
				pImportTable->FirstThunk += addedSize;
			}
		}
		*/
		// 下一张导入表
		pImportTable++;
	}
}
VOID FixBaseReloc(PVOID fileHandle, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	BOOL is32bit = TRUE;
	if (peMainInfo->Magic == 0x010b) {
		is32bit = is32bit;
	}
	else if (peMainInfo->Magic == 0x020b) {
		is32bit = !is32bit;
	}
	else {
		return FALSE;
	}
	PIMAGE_DATA_DIRECTORY pBaseRelocTableDir = &peMainInfo->BaseReloc;
	if (pBaseRelocTableDir->VirtualAddress == 0) {
		LogBaseRelocTable("重定位不存在", "None");
		return 0;
	}
	PIMAGE_BASE_RELOCATION pBaseRelocTable = (PIMAGE_BASE_RELOCATION)(RvaToFva2(fileHandle, peOffset, pBaseRelocTableDir->VirtualAddress, peMainInfo->Magic) + (LONG64)fileHandle);
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
			// 找到要修改的硬编码
			PVOID changedAddr = (PVOID)(RvaToFva2(fileHandle, peOffset, baseRva + offset, peMainInfo->Magic) + (LONG64)fileHandle);
			// 只有高位是3，该地址才需要重定位，内容修改
			if (is32bit) {
				if (type == IMAGE_REL_BASED_HIGHLOW) {
					DWORD rvaNow = *(PDWORD)changedAddr - (DWORD)peMainInfo->ImageBase;
					if (FindSection(rvaNow, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
						*(PDWORD)changedAddr += addedSize;
					}
				}
			}
			else {
				if (type == 0xa) {
					DWORD rvaNow = *(PLONG64)changedAddr - (LONG64)peMainInfo->ImageBase;
					if (FindSection(rvaNow, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
						*(PLONG64)changedAddr += addedSize;
					}
				}
			}
		}
		// 修改基本值; 如果这个基本值对应的偏移恰好穿插于分割线，那么会有点问题；
		if (FindSection(baseRva, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
			pBaseRelocTable->VirtualAddress += AddedDataLength(addedSize, 0x1000) * 0x1000;
		}
		LogBaseRelocTable("重定位表修改后基址", "0x%x", pBaseRelocTable->VirtualAddress);
		pBaseRelocTable = (PIMAGE_BASE_RELOCATION)((LONG64)pBaseRelocTable + pBaseRelocTable->SizeOfBlock);
	}
}
VOID FixDataDirectory(PVOID fileHandle, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	// 打印PE可选头中的16张表的相关信息
	PCHAR dataDirName[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
		"EXPORT","IMPORT","RESOURCE","EXCEPTION","SECURITY",
		"BASE RELOC","DEBUG","COPYRIGHT","GLOBAL PTR","TLS",
		"LOAD CONFIG","BOUND IMPORT","IAT","DLID","CLR HEADER",
		"NOT USED"
	};
	PIMAGE_DATA_DIRECTORY pNtDataDir = (PIMAGE_DATA_DIRECTORY)(peMainInfo->DataDir + (LONG64)fileHandle);
	for (DWORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		if (FindSection(pNtDataDir->VirtualAddress, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
			pNtDataDir->VirtualAddress += addedSize;
		}
		pNtDataDir++;
	}
}
VOID FixResourceTable(PVOID fileHandle, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	PIMAGE_RESOURCE_DIRECTORY pResourceTableRoot = (PIMAGE_RESOURCE_DIRECTORY)(RvaToFva(fileHandle, peOffset, peMainInfo->Resource) + (LONG64)fileHandle);
	// 计算二级目录数
	DWORD numberOfSecond = pResourceTableRoot->NumberOfIdEntries + pResourceTableRoot->NumberOfNamedEntries;
	// 二级开始的位置
	PIMAGE_RESOURCE_DIRECTORY_ENTRY firstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceTableRoot + 1);
	for (LONG64 i = 0; i < numberOfSecond; i++) {
		TraverseAndFixDirectory((LONG64)pResourceTableRoot, fileHandle, peOffset, addedSize, index, peMainInfo, firstEntry, 1, pImageSectionHeader);
		firstEntry++;
	}
}
VOID TraverseAndFixDirectory(PVOID fileHandle, PVOID fileHandle2, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_RESOURCE_DIRECTORY_ENTRY nowEntry, DWORD level, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	if (nowEntry->DataIsDirectory) {
		PIMAGE_RESOURCE_DIRECTORY newEntry = (PIMAGE_RESOURCE_DIRECTORY)(nowEntry->OffsetToDirectory + (LONG64)fileHandle);
		// 计算三级目录数
		DWORD numberOfSecond = newEntry->NumberOfIdEntries + newEntry->NumberOfNamedEntries;
		// 三级开始的位置
		PIMAGE_RESOURCE_DIRECTORY_ENTRY firstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(newEntry + 1);
		for (LONG64 i = 0; i < numberOfSecond; i++) {
			TraverseAndFixDirectory(fileHandle, fileHandle2, peOffset, addedSize, index, peMainInfo, firstEntry, level + 1, pImageSectionHeader);
			firstEntry++;
		}
	}else {
		// 资源文件
		PIMAGE_RESOURCE_DATA_ENTRY newDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(nowEntry->OffsetToData + (LONG64)fileHandle);
		if (FindSection(newDataEntry->OffsetToData, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
			newDataEntry->OffsetToData += addedSize;
		}
		// LogResource("资源文件rva", level, "0x%x, 资源文件大小：0x%x", newDataEntry->OffsetToData, newDataEntry->Size);
	}
}

/**
* 功能： 传入一个RVA，返回其存在于哪个节区，节区有:-1 0 1 2 3 4 ...；-1意味着它不会发生改变（存在于第一个节之前）
*/
LONG64 FindSection(DWORD rva, DWORD numberOfSections, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	// RVA在第一个节之前，返回-1;因为所有的增加操作是从节头表之后开始进行的。
	if (rva < pImageSectionHeader->PointerToRawData) {
		return -1;
	}
	LONG64 count = 0;
	for (count = 0; count < numberOfSections; count++) {
		// 求出节内偏移
		LONG64 baseSection = pImageSectionHeader->VirtualAddress;
		LONG64 virtualSize = pImageSectionHeader->Misc.VirtualSize;
		LONG64 baseFileSection = pImageSectionHeader->PointerToRawData;
		// 找到对应节
		if (rva >= baseSection && rva <= baseSection + virtualSize) {
			if (count < numberOfSections - 1 && rva == (pImageSectionHeader + 1)->VirtualAddress) {
				count++;
			}
			break;
		}
		pImageSectionHeader++;
	}
	if (count >= numberOfSections) {
		Log("未定位到对应的RVA地址","Warning",0);
	}
	return count;
}

// 扩大某个节

// 将文件对齐改为与内存对齐一致

// 修复IAT

// 通过重定位表进行重定位操作



/**
*	功能：	RVA to FVA
*   参数：	PE文件映射至内存的指针，RVA
*	返回值：FVA
*/
LONG64 RvaToFva2(PVOID fileHandle, LONG peOffset, LONG64 rva, DWORD magic) {
	BOOL is32bit = TRUE;
	if (magic == 0x010b) {
		is32bit = is32bit;
	}
	else if (magic == 0x020b) {
		is32bit = !is32bit;
	}
	else {
		return FALSE;
	}

	if (is32bit) {
		// pe头
		PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((LONG64)fileHandle + peOffset);
		// PE文件头
		PIMAGE_FILE_HEADER pNtFileHeader = &pNtHeaders->FileHeader;
		// PE可选头
		PIMAGE_OPTIONAL_HEADER32 pNtOpHeader = &pNtHeaders->OptionalHeader;
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
			PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LONG64)fileHandle + peOffset + sizeof(IMAGE_NT_HEADERS32));
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
					break;
				}
				pImageSectionHeader++;
			}
		}
		return fva;
	}else {
		// pe头
		PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((LONG64)fileHandle + peOffset);
		// PE文件头
		PIMAGE_FILE_HEADER pNtFileHeader = &pNtHeaders->FileHeader;
		// PE可选头
		PIMAGE_OPTIONAL_HEADER64 pNtOpHeader = &pNtHeaders->OptionalHeader;
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
			PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LONG64)fileHandle + peOffset + sizeof(IMAGE_NT_HEADERS64));
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
					break;
				}
				pImageSectionHeader++;
			}
		}
		return fva;
	}
}