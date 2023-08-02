#define TYPE 1 // 0 =>32  1 =>64
#include "pe.h"

/**
*	���ܣ�	�жϵ�ǰ�ļ���λ��
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ��
*	����ֵ��
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
		Log("δʶ����ļ�λ��", "error", -1);
		exit(-1);
	}
	*/
}

LONG64 AnalyzeResourceTable(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure) {
	PIMAGE_RESOURCE_DIRECTORY pResourceTableRoot = (PIMAGE_RESOURCE_DIRECTORY)(RvaToFva(fileHandle, peOffset, pPeStructure->pPeNtOptionalData->Resource) + (LONG64)fileHandle);
	// �������Ŀ¼��
	DWORD numberOfSecond = pResourceTableRoot->NumberOfIdEntries + pResourceTableRoot->NumberOfNamedEntries;
	// ������ʼ��λ��
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
			LogResource("��ԴĿ¼����", level, "%S, %d��Ŀ¼", name, level);
		}else {
			LogResource("��ԴĿ¼ID�����ͣ�", level, "0x%x, %d��Ŀ¼", nowEntry->Id, level);
		}
		PIMAGE_RESOURCE_DIRECTORY newEntry = (PIMAGE_RESOURCE_DIRECTORY)(nowEntry->OffsetToDirectory + (LONG64)fileHandle);
		// ��������Ŀ¼��
		DWORD numberOfSecond = newEntry->NumberOfIdEntries + newEntry->NumberOfNamedEntries;
		// ������ʼ��λ��
		PIMAGE_RESOURCE_DIRECTORY_ENTRY firstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(newEntry + 1);
		for (LONG64 i = 0; i < numberOfSecond; i++) {
			TraverseDirectory(fileHandle, peOffset, firstEntry, level + 1);
			firstEntry++;
		}
	}else {
		// ��Դ�ļ���
		if (nowEntry->NameIsString) {
			PIMAGE_RESOURCE_DIR_STRING_U pNameStart = (PIMAGE_RESOURCE_DIR_STRING_U)(nowEntry->NameOffset + (LONG64)fileHandle);
			DWORD len = pNameStart->Length + 2;
			PWCHAR name = (PWCHAR)malloc(sizeof(WCHAR) * len);
			if (!name) {
				exit(-10086);
			}
			memset(name, 0x0, sizeof(WCHAR) * len);
			RtlCopyMemory(name, pNameStart->NameString, pNameStart->Length * sizeof(WCHAR));
			LogResource("��Դ�ļ�����", level, "%S, %d��Ŀ¼���ļ�", name, level);
		}else {
			LogResource("��Դ�ļ�ID�����ͣ�", level, "%d, %d��Ŀ¼���ļ�", nowEntry->Id, level);
		}
		PIMAGE_RESOURCE_DATA_ENTRY newDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(nowEntry->OffsetToData + (LONG64)fileHandle);
		LogResource("��Դ�ļ�rva", level, "0x%x, ��Դ�ļ���С��0x%x", newDataEntry->OffsetToData, newDataEntry->Size);
	}
}

/**
*	���ܣ�	����32/64λPE�ļ����ض�λ�������Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ�ƣ�PPEStructure�ṹ��
*	����ֵ��
*/
LONG64 AnalyzeBaseRelocTable(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure) {
	SplitLine();
	if (pPeStructure->pPeNtOptionalData->BaseReloc.VirtualAddress == 0) {
		LogBaseRelocTable("�ض�λ������", "None");
		return 0;
	}
	PIMAGE_DATA_DIRECTORY pBaseRelocTableDir = &pPeStructure->pPeNtOptionalData->BaseReloc;
	PIMAGE_BASE_RELOCATION pBaseRelocTable = (PIMAGE_BASE_RELOCATION)(RvaToFva(fileHandle, peOffset, pBaseRelocTableDir->VirtualAddress) + (LONG64)fileHandle);
	// ��ЩPE��VirtualAddress����0x1
	while (pBaseRelocTable->VirtualAddress != 0x00000000 && pBaseRelocTable->VirtualAddress != 0x00000001) {
		DWORD numberOfData = (pBaseRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		DWORD baseRva = pBaseRelocTable->VirtualAddress;
		// ָ���һ���������
		PWORD dataStart = (PWORD)(pBaseRelocTable + 1);
		// ��������
		for (DWORD i = 0; i < numberOfData; i++) {
			DWORD type = dataStart[i] >> 0xc;
			DWORD offset = dataStart[i] & 0x0fff;
			LogBaseRelocTable("�ض�λ���ݵĻ�ַRVA", "0x%x, ��Ի�ַƫ��RVA��0x%x, ����ƫ�ƣ�0x%x", baseRva, offset, i);
		}
		pBaseRelocTable = (PIMAGE_BASE_RELOCATION)((LONG64)pBaseRelocTable + pBaseRelocTable->SizeOfBlock);
	}
}

/**
*	���ܣ�	����32/64λPE�ļ��ĵ����������Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ�ƣ�PPEStructure�ṹ��
*	����ֵ��
*/
LONG64 AnalyzeExportTable(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure) {
	SplitLine();
	if (pPeStructure->pPeNtOptionalData->Export.VirtualAddress == 0) {
		LogExportTable("����������","None");
		return 0;
	}
	// ��λ��������
	PIMAGE_DATA_DIRECTORY pExportDataDir = &pPeStructure->pPeNtOptionalData->Export;
	// �������λ�ã�ֻ��һ�ŵ�����
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(RvaToFva(fileHandle, peOffset, pExportDataDir->VirtualAddress) + (LONG64)fileHandle);
	// ��ӡ������Ϣ
	LogExportTable("DLL Name", "%s", (PCHAR)(RvaToFva(fileHandle, peOffset, pExportTable->Name) + (LONG64)fileHandle));
	LogExportTable("Characteristics", "%08x", pExportTable->Characteristics);
	LogExportTable("Time Data Stamp", "%08x", pExportTable->TimeDateStamp);
	LogExportTable("MajorVersion", "%04x", pExportTable->MajorVersion);
	LogExportTable("MinorVersion", "%04x", pExportTable->MinorVersion);
	LogExportTable("Base", "%08x", pExportTable->Base); // ʹ����ŵ����ĺ�������ʼ��ţ�������� - ��ʼ��� => ������ַ���е�����
	LogExportTable("Number Of Functions", "%08x", pExportTable->NumberOfFunctions);
	LogExportTable("Number Of Names", "%08x", pExportTable->NumberOfNames);
	LogExportTable("Address Of Functions", "%08x", pExportTable->AddressOfFunctions);  //RVA
	LogExportTable("Address Of Names", "%08x", pExportTable->AddressOfNames);   //RVA
	LogExportTable("Address Of Name Ordinals", "%08x", pExportTable->AddressOfNameOrdinals);  //RVA
	// ��ȡ���ź�����ر����Ϣ
	DWORD *funcAddressTable = (DWORD *)(RvaToFva(fileHandle, peOffset, pExportTable->AddressOfFunctions) + (LONG64)fileHandle); // ������ַ�� 
	DWORD *funcNameTable = (DWORD *)(RvaToFva(fileHandle, peOffset, pExportTable->AddressOfNames) + (LONG64)fileHandle); // �������Ʊ�
	WORD *funcNameOrdinalsTable = (WORD *)(RvaToFva(fileHandle, peOffset, pExportTable->AddressOfNameOrdinals) + (LONG64)fileHandle); // ��������˳���
	DWORD numberOfNames = pExportTable->NumberOfNames;
	DWORD numberOfFuncs = pExportTable->NumberOfFunctions;
	DWORD base = pExportTable->Base;
	for (DWORD i = 0; i < numberOfFuncs; i++) {
		if (funcAddressTable[i] == 0) {
			continue; // �յģ�Ҳ����˵�������Ǳ������˵�
		}
		DWORD j = 0;
		for (; j < numberOfNames; j++) {
			if (funcNameOrdinalsTable[j] == i) {
				PCHAR name = (PCHAR)(RvaToFva(fileHandle, peOffset, funcNameTable[j]) + (LONG64)fileHandle);
				WORD ordinal = base + i;
				DWORD address = funcAddressTable[i];
				LogExportTable("��������", "%s, ������� : %04x, ������ַ(RVA)�� %08x, �����ļ���ַ(FVA): %08I64x", name, ordinal, address, RvaToFva(fileHandle, peOffset, address));
				break;
			}
		}
		if (j == numberOfNames) {
			WORD ordinal = base + i;
			DWORD address = funcAddressTable[i];
			LogExportTable("��������", "NULL, ������� : %04x, ������ַ(RVA)�� %08x, �����ļ���ַ(FVA): %08I64x", ordinal, address, RvaToFva(fileHandle, peOffset, address));
		}
	}
	return 0;
}

/**
*	���ܣ�	����32/64λPE�ļ��ĵ���������Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ�ƣ�PPEStructure�ṹ��
*	����ֵ��
*/
LONG64 AnalyzeImportTable(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure) {
	SplitLine();
	if (pPeStructure->pPeNtOptionalData->Import.VirtualAddress == 0) {
		LogImportTable("���������","None");
		return 0;
	}
	// �ҵ�����Ŀ¼���еĵ���������Ϣ
	PIMAGE_DATA_DIRECTORY pImportDataDir = &pPeStructure->pPeNtOptionalData->Import;
	// ��ȡ��һ�ŵ����ĵ�ַ
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFva(fileHandle, peOffset, pImportDataDir->VirtualAddress) + (LONG64)fileHandle);
	while (pImportTable->Characteristics != 0) {
		// ��ȡ����������
		LONG64 fva = RvaToFva(fileHandle, peOffset, pImportTable->Name);
		LogImportTable("dll����", "%s", (PCHAR)(fva + (LONG64)fileHandle));
		// ����INT  pImportTable->OriginalFirstThunk => THUNK_DATA����
		fva = RvaToFva(fileHandle, peOffset, pImportTable->OriginalFirstThunk);
		// fva = RvaToFva(fileHandle, peOffset, pImportTable->FirstThunk);
		PMYIMAGE_THUNK_DATA pImportNameTable = (PMYIMAGE_THUNK_DATA)(fva + (LONG64)fileHandle);
		while (pImportNameTable->u1.Ordinal != 0) {
			// �ж����λ�Ƿ�Ϊ1
#ifdef x86_PROGRAM
			if ((pImportNameTable->u1.Ordinal & 0x80000000) >> 31 != 1) {
#endif
#ifdef x64_PROGRAM
				if ((pImportNameTable->u1.Ordinal & 0x8000000000000000) >> 63 != 1) {
#endif
				// ���λ��Ϊ1��˵���ú������к�����Ҳ�����
				fva = RvaToFva(fileHandle, peOffset, pImportNameTable->u1.AddressOfData);
				PIMAGE_IMPORT_BY_NAME pTableFunc = (PIMAGE_IMPORT_BY_NAME)(fva + (LONG64)fileHandle);
				LogImportTable("�������", "%04x, �������� : %s", pTableFunc->Hint, pTableFunc->Name); // ˵��ÿ��PIMAGE_THUNK_DATA32�Ĵ�С����name���ԵĴ��ڣ����ǲ��̶��ġ�
			}else {
				// ���λΪ1
#ifdef x86_PROGRAM
				LogImportTable("�������", "%04x", pImportNameTable->u1.Ordinal & 0x7fffffff);
#endif
#ifdef x64_PROGRAM
				LogImportTable("�������", "%016I64x", pImportNameTable->u1.Ordinal & 0x7fffffffffffffff);
#endif
			}
			// ��һ������
			pImportNameTable++;
		}
		// ��һ�ŵ����
		pImportTable++;
	}
	return 0;
}

/**
*	���ܣ�	RVA to FVA
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬RVA
*	����ֵ��FVA
*/
LONG64 RvaToFva(PVOID fileHandle , LONG peOffset, LONG64 rva){
	// peͷ
	PMYIMAGE_NT_HEADERS pNtHeaders = (PMYIMAGE_NT_HEADERS)((LONG64)fileHandle + peOffset);
	// PE�ļ�ͷ
	PIMAGE_FILE_HEADER pNtFileHeader = &pNtHeaders->FileHeader;
	// PE��ѡͷ
	PMYIMAGE_OPTIONAL_HEADER pNtOpHeader = &pNtHeaders->OptionalHeader;
	// ����Ŀ¼������
	PIMAGE_DATA_DIRECTORY pNtDataDir = pNtOpHeader->DataDirectory;

	// �����ļ���Χ�����Ϸ���
	if (rva > pNtOpHeader->SizeOfImage || rva < 0) {
		return 0;
	}
	// ���ļ��������ڴ����ͬ��ʱ
	LONG64 fva = rva;
	LONG64 fileAlignment = pNtOpHeader->FileAlignment;
	LONG64 sectionAlignment = pNtOpHeader->SectionAlignment;
	if (fileAlignment != sectionAlignment) {
		PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LONG64)fileHandle + peOffset + sizeof(MYIMAGE_NT_HEADERS));
		LONG64 numberOfSections = pNtFileHeader->NumberOfSections;
		#pragma warning(disable: 6305)
		LONG64 endSectionHeaders = (LONG64)pImageSectionHeader + numberOfSections * sizeof(IMAGE_SECTION_HEADER) - (LONG64)fileHandle;
		// �ڽڱ�ͷ��֮ǰ��PE�ṹ�Ǿ������еġ�
		if (rva <= endSectionHeaders) {
			return fva;
		}
		// �ڽڱ�ͷ֮�󵽵�һ���ڱ�֮�䣬rva��������ġ�
		if (rva > endSectionHeaders && rva < pImageSectionHeader->VirtualAddress) {
			return 0;
		}
		for (LONG64 i = 0; i < numberOfSections; i++) {
			// �������ƫ��
			LONG64 baseSection = pImageSectionHeader->VirtualAddress;
			LONG64 virtualSize = pImageSectionHeader->Misc.VirtualSize;
			LONG64 baseFileSection = pImageSectionHeader->PointerToRawData;
			// RVA��������֮��Ŀհ�����ʱ��������
			if (i < numberOfSections - 1 && rva > baseSection + virtualSize && rva < (pImageSectionHeader + 1)->VirtualAddress) {
				return 0;
			}
			// �ҵ���Ӧ��
			if (rva >= baseSection && rva <= baseSection + virtualSize) {
				// ����ƫ��
				LONG64 sectionOffset = rva - baseSection;
				// ����fva��fva������ļ�0ƫ�ƴ�����ģ�rva������ļ��ڴ�ӳ�䴦��ʼ�����
				fva = baseFileSection + sectionOffset;
				// ����������������Կ�������û������������
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
*	���ܣ�	��ӡ32/64λPE�ļ��Ľڱ������Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ�ƣ�PPEStructure�ṹ��
*	����ֵ��
*/
LONG64 AnalyzeSectionHeader(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure) {
	/* �ú궨������Ѱ�ҵ�һ���ڱ�ͷ
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
		Log("PPeSectionGaps����ѿռ�ʧ��", "error", GetLastError());
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
			// ������Դ��Ļ�
			pPeStructure->pPeNtOptionalData->Resource = pImageSectionHeader->VirtualAddress;
		}
		LogSecHeader("�ڱ�����", "%s", pImageSectionHeader->Name);
		LogSecHeader("VirtualSize", "%08x", pImageSectionHeader->Misc.VirtualSize);   // �ڴ��еĽڴ�С
		LogSecHeader("VirtualAddress", "%08x", pImageSectionHeader->VirtualAddress);      // ��ǰ�ڵ��ڴ�ƫ��
		LogSecHeader("Size Of Raw Data", "%08x", pImageSectionHeader->SizeOfRawData);  // �ļ��еĽڴ�С
		LogSecHeader("Pointer To Raw Data", "%08x", pImageSectionHeader->PointerToRawData); // ��ǰ�ڵ��ļ�ƫ��
		LogSecHeader("Pointer To Relocations", "%08x", pImageSectionHeader->PointerToRelocations); // OBJ�ļ�ʹ��
		LogSecHeader("Pointer To Line Numbers", "%08x", pImageSectionHeader->PointerToLinenumbers); // OBJ�ļ�ʹ��
		LogSecHeader("Number Of Relocations", "%04x", pImageSectionHeader->NumberOfRelocations); // OBJ�ļ�ʹ��
		LogSecHeader("Number Of Line Numbers", "%04x", pImageSectionHeader->PointerToLinenumbers); // OBJ�ļ�ʹ��
		LogSecHeader("Characteristics", "%08x", pImageSectionHeader->Characteristics); // ������
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
*	���ܣ�	��ӡ32λPE�ļ���PEͷ�����Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ��
*	����ֵ������PEStructure��
*/
PPEStructure AnalyzeNtHeader(PVOID fileHandle, LONG peOffset) {
	SplitLine();
	PMYIMAGE_NT_HEADERS pNtHeaders = (PMYIMAGE_NT_HEADERS)((LONG64)fileHandle + peOffset);
	// PE�ļ�ͷ
	PIMAGE_FILE_HEADER pNtFileHeader = &pNtHeaders->FileHeader;
	// PE��ѡͷ
	PMYIMAGE_OPTIONAL_HEADER pNtOpHeader = &pNtHeaders->OptionalHeader;
	// ����Ŀ¼������
	PIMAGE_DATA_DIRECTORY pNtDataDir = pNtOpHeader->DataDirectory;

	// �ļ�ͷ��������Ϣ
	PPeNtFileHeaderData pPeNtFileData = (PPeNtFileHeaderData)malloc(sizeof(PeNtFileHeaderData));
	memset(pPeNtFileData, 0x0, sizeof(PeNtFileHeaderData));
	if (!pPeNtFileData) {
		Log("PeNtFileHeaderData����ѿռ�ʧ��", "error", GetLastError());
	}else {
		pPeNtFileData->NumberOfSections = pNtFileHeader->NumberOfSections;
		pPeNtFileData->Characteristics = pNtFileHeader->Characteristics;
		pPeNtFileData->SizeOfOptionalHeader = pNtFileHeader->SizeOfOptionalHeader;
	}
	// �ļ�ͷ��������Ϣ
	PPeNtOptionalHeaderData pPeNtOptionalData = (PPeNtOptionalHeaderData)malloc(sizeof(PeNtOptionalHeaderData));
	memset(pPeNtOptionalData, 0x0, sizeof(PeNtOptionalHeaderData));
	if (!pPeNtOptionalData) {
		Log("PPeNtOptionalHeaderData����ѿռ�ʧ��", "error", GetLastError());
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
	// ����PPEStructure�ռ�
	PPEStructure pPeStructure = (PPEStructure)malloc(sizeof(PEStructure));
	memset(pPeStructure, 0x0, sizeof(PEStructure));
	if (!pPeStructure) {
		Log("Px86PEStructure����ѿռ�ʧ��", "error", GetLastError());
	}else {
		pPeStructure->pPeNtFileData = pPeNtFileData;
		pPeStructure->pPeNtOptionalData = pPeNtOptionalData;
		// ��ǰ����ڱ�ͷ�Ŀ�ʼλ��RVA
		pPeStructure->SectionHeader = peOffset + sizeof(MYIMAGE_NT_HEADERS);
	}
	// ��ӡPE��ʶ�Լ�PE�ļ�ͷ����Ϣ
	LogNtHeader("NT Magic", "%c%c", (CHAR)pNtHeaders->Signature, *(PCHAR)((LONG64)&pNtHeaders->Signature + 1));
	LogNtHeader("NtFileHeader Machine", "%04x", pNtFileHeader->Machine);
	LogNtHeader("NtFileHeader Number Of Section", "%04x", pNtFileHeader->NumberOfSections);
	LogNtHeader("NtFileHeader Time Date Stamp", "%08x", pNtFileHeader->TimeDateStamp);
	LogNtHeader("NtFileHeader Pointer to Symbol Table", "%08x", pNtFileHeader->PointerToSymbolTable);
	LogNtHeader("NtFileHeader Number Of Symbols", "%08x", pNtFileHeader->NumberOfSymbols);
	LogNtHeader("NtFileHeader Size of Optional Header", "%04x", pNtFileHeader->SizeOfOptionalHeader); // �����Լ�����Ŀ¼��
	LogNtHeader("NtFileHeader Characteristics", "%04x", pNtFileHeader->Characteristics);
	// ��ӡPE��ѡͷ�ı�׼������Ϣ
#ifdef x86_PROGRAM
	LogNtHeader("NtOptionalHeader Magic", "%04x  %s", pNtOpHeader->Magic, "32 bit");
#endif
#ifdef x64_PROGRAM
	LogNtHeader("NtOptionalHeader Magic", "%04x  %s", pNtOpHeader->Magic, "64 bit");
#endif
	LogNtHeader("NtOptionalHeader MajorLinerVersion", "%02x", pNtOpHeader->MajorLinkerVersion);
	LogNtHeader("NtOptionalHeader MinorLinerVersion", "%02x", pNtOpHeader->MinorLinkerVersion);
	LogNtHeader("NtOptionalHeader Size Of Code", "%08x", pNtOpHeader->SizeOfCode);  // ����δ�С
	LogNtHeader("NtOptionalHeader Size Of Initialized Data", "%08x", pNtOpHeader->SizeOfInitializedData);
	LogNtHeader("NtOptionalHeader Size Of Uninitialized Data", "%08x", pNtOpHeader->SizeOfUninitializedData);
	LogNtHeader("NtOptionalHeader Address Of Entry Point", "%08x", pNtOpHeader->AddressOfEntryPoint);
	LogNtHeader("NtOptionalHeader Base Of Code", "%08x", pNtOpHeader->BaseOfCode);
#ifdef x86_PROGRAM
	LogNtHeader("NtOptionalHeader Base Of Data", "%08x", pNtOpHeader->BaseOfData);
#endif
	// ��ӡPE��ѡͷ�еĸ���������Ϣ
#ifdef x86_PROGRAM
	LogNtHeader("NtOptionalHeader Image Base", "%08x", pNtOpHeader->ImageBase); //�ļ�Ԥ��ļ������ڴ��еĻ�ַ 
#endif
#ifdef x64_PROGRAM
	LogNtHeader("NtOptionalHeader Image Base", "%016I64x", pNtOpHeader->ImageBase); //�ļ�Ԥ��ļ������ڴ��еĻ�ַ 
#endif
	LogNtHeader("NtOptionalHeader Section Alignment", "%08x", pNtOpHeader->SectionAlignment); // �����ڴ�����С
	LogNtHeader("NtOptionalHeader File Alignment", "%08x", pNtOpHeader->FileAlignment); // �����ļ������С
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
	LogNtHeader("NtOptionalHeader Subsystem", "%04x", pNtOpHeader->Subsystem);  // �ļ�����������ϵͳ
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
	// ��ӡPE��ѡͷ�е�16�ű�������Ϣ
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
				// ����IAT					
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
				pPeNtOptionalData->IAT.VirtualAddress = pNtDataDir->VirtualAddress; // �����ռ���IAT�ǲ�׼ȷ��
			}
		}
		LogNtHeader("NtOptionalHeader Data Directory", "%s => RVA: %08x, Size: %08x�� FVA: %08I64x",
			dataDirName[i], pNtDataDir->VirtualAddress, pNtDataDir->Size, RvaToFva(fileHandle, peOffset, pNtDataDir->VirtualAddress));
		pNtDataDir++;
	}
	return pPeStructure;
}

/**
*	���ܣ�	��ӡDOSͷ�����Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ��
*	����ֵ��PEͷ��ƫ��
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
*	���ܣ�	��ָ��·�����ļ�
*   ������	PE�ļ��洢·��
*	����ֵ��PE�ļ�ӳ�����ڴ��ָ��
*/
PVOID OpenPeFile(const char* filePath) {
	// ���ļ�
	HANDLE fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// ��ȡ�ļ���С
	PLARGE_INTEGER fileSize = (PLARGE_INTEGER)malloc(sizeof(LARGE_INTEGER));
	if (!fileSize) {
		Log("��̬����洢�ļ���С�ı���ʧ��", "error", GetLastError());
		return NULL;
	}
	memset(fileSize, 0x0, sizeof(LARGE_INTEGER));
	BOOL ok = GetFileSizeEx(fileHandle, fileSize);
	LogData(filePath, "�ļ���С", "0x%x", fileSize->LowPart);
	// ��������ҳ���������ļ�����
	HANDLE memHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, fileSize->u.HighPart, fileSize->u.LowPart, NULL);
	if (!memHandle) {
		Log("CreateFileMappingA����ʧ��", "error", GetLastError());
		return NULL;
	}
	// ������ҳ�������ַ���йҹ�
	LPVOID memFile = MapViewOfFile(memHandle, FILE_MAP_READ, 0, 0, fileSize->QuadPart);
	// �ͷ���Դ
	CloseHandle(fileHandle);
	CloseHandle(memHandle);
	free(fileSize);
	return memFile;
}
