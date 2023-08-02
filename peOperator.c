#define TYPE 0
#include "pe.h"

/**
*	���ܣ�	����INT�еĺ������ƻ���Ż�ȡ��Ӧ�����ĵ�ַ������������PE�ļ���IAT����
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬PPEStructure
*	����ֵ��
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
			// 32λ����
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
			// 64λ����
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
*	���ܣ�	���ӽڱ�
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬PPEStructure    λ�ô�1��ʼ
*	����ֵ���µ��ļ���С
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
	// ���ڵ��ļ���С�� ���ڴ潫�޸ĺ���ļ�д�����ʱʹ��
	DWORD now_size = 0;
	for (DWORD i = 0; i < numberOfSections; i++) {
		now_size = pImageSectionHeader->PointerToRawData + pImageSectionHeader->SizeOfRawData;
		pImageSectionHeader++;
	}
	// �ڱ�ǰ�Ŀ��пռ�
	DWORD sectionGap = FirstSection + (LONG64)fileHandle - (LONG64)pImageSectionHeader;
	// �ļ�����
	DWORD fileAlignment = 0;
	// �ڴ����
	DWORD memAlignment = 0;
	// �µĽ�����
	DWORD sectionSize = 0;
	// �ڴ����ӵ�����������Size Of Imageʱʹ��
	DWORD addedMem = 0;
	// ���нڶ�Ҫ���ӵ��ļ���С�� ����������ʱʹ��
	DWORD addedFile = 0;
	// �޸�PEͷ�еĽ�����
	if (is32bit) {
		PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((LONG64)fileHandle + peOffset);
		sectionSize = pNtHeaders->FileHeader.NumberOfSections;
		pNtHeaders->FileHeader.NumberOfSections += 1;
		// ��ȡ�ļ�����
		fileAlignment = pNtHeaders->OptionalHeader.FileAlignment;
		// ��ȡ�ڴ����
		memAlignment = pNtHeaders->OptionalHeader.SectionAlignment;
	}else {
		PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((LONG64)fileHandle + peOffset);
		sectionSize = pNtHeaders->FileHeader.NumberOfSections;
		pNtHeaders->FileHeader.NumberOfSections += 1;
		// ��ȡ�ļ�����
		fileAlignment = pNtHeaders->OptionalHeader.FileAlignment;
		memAlignment = pNtHeaders->OptionalHeader.SectionAlignment;
	}
	// ����newSecSize
	newSecSize = AddedDataLength(newSecSize, fileAlignment) * fileAlignment;

	// �жϽ�ͷ���ܲ���������Ϣ
	if (sectionGap < (DWORD)sizeof(IMAGE_SECTION_HEADER)) {
		// ˵����һ����ǰ�Ŀռ䲻������һ���ڱ�, ��Ҫ�����н�����ƶ������ʱ���ض�λ�����Ϣ�ǻ��ܵ�Ӱ���!

		// �˲����漰�Ķ࣬��δ����

		// �����ļ���С,�����С���������������µĽڱ�ͷ��
		now_size += fileAlignment;
		// �����ڴ��С
		addedMem += memAlignment;
		// ���ӵ��ļ���С
		addedFile += fileAlignment;
	}

	// �޸�PE����
	FixPeFile(fileHandle, peOffset, AddedDataLength(newSecSize, fileAlignment) * memAlignment, location - 1, peMainInfo, pOrgImageSectionHeader);

	// �洢����ǰ�Ľ���Ϣ
	DWORD lastPointerRaw = 0;
	DWORD lastPointerFileRaw = 0;
	// �ƶ������ڣ��������½�
	if (sectionSize < location) {
		// ������һ��λ����չһ���ڣ�Ĭ�����������չ
		// �������һ����,�ռ�������ǰ�������
		now_size += newSecSize;
		addedMem += (newSecSize / fileAlignment) * memAlignment;
		// ����һ����ͷ����,������������     // ����ദ��Ҫ����һ��
		strcpy_s(pImageSectionHeader->Name, IMAGE_SIZEOF_SHORT_NAME, ".adddd");
		pImageSectionHeader->Misc.VirtualSize = AddedDataLength(newSecSize, fileAlignment) * memAlignment;
		pImageSectionHeader->VirtualAddress = (pImageSectionHeader - 1)->VirtualAddress + AddedDataLength((pImageSectionHeader - 1)->Misc.VirtualSize, memAlignment) * memAlignment;
		pImageSectionHeader->SizeOfRawData = AddedDataLength(newSecSize, fileAlignment) * fileAlignment;
		pImageSectionHeader->PointerToRawData = (pImageSectionHeader - 1)->PointerToRawData + AddedDataLength((pImageSectionHeader - 1)->SizeOfRawData, fileAlignment) * fileAlignment;
		pImageSectionHeader->Characteristics = (pImageSectionHeader - 1)->Characteristics;
	}else {
		now_size += newSecSize;
		addedMem += (newSecSize / fileAlignment) * memAlignment;
		// �ڵ�location���ڴ�����һ���ڣ������±�Ϊlocation - 1
		for (LONG64 i = (LONG64)numberOfSections - 1; i >= 0; i--) {
			// ��������������һ���ڣ�������ǻ�Ӱ�쵽�ض�λ���ڵ����ݵģ�������˴����;���ǿ��Ա����ض�λ���޸��ض�λ�����Ϣ��
			// �ƶ��ڱ�����
			RtlMoveMemory((LONG64)fileHandle + (pImageSectionHeader - 1)->PointerToRawData + (LONG64)newSecSize, (LONG64)fileHandle + (pImageSectionHeader - 1)->PointerToRawData, (pImageSectionHeader - 1)->SizeOfRawData);
			// �޸��ڱ�ͷ�������ַ
			if (FindSection((pImageSectionHeader - 1)->VirtualAddress, peMainInfo->NumberOfSections, pOrgImageSectionHeader) >= location - 1) {
				lastPointerRaw = (pImageSectionHeader - 1)->VirtualAddress;
				(pImageSectionHeader - 1)->VirtualAddress += AddedDataLength(newSecSize, fileAlignment) * memAlignment;
			}
			// �ƶ���ͷ��
			RtlMoveMemory(pImageSectionHeader, pImageSectionHeader - 1, sizeof(IMAGE_SECTION_HEADER));
			// �����ڱ���ļ�ָ��
			lastPointerFileRaw = pImageSectionHeader->PointerToRawData;
			pImageSectionHeader->PointerToRawData += AddedDataLength(newSecSize ,fileAlignment) * fileAlignment; // ������Ҫ����һ��
			if (i == location - 1) {
				// �������һ����Ҫ�ƶ��Ľ���
				RtlZeroMemory((LONG64)fileHandle + (pImageSectionHeader - 1)->PointerToRawData, newSecSize);
				break;
			}
			pImageSectionHeader--;
		}
		// ����һ����ͷ����,������������
		strcpy_s((pImageSectionHeader-1)->Name, IMAGE_SIZEOF_SHORT_NAME, ".adddd");
		(pImageSectionHeader-1)->Misc.VirtualSize = AddedDataLength(newSecSize ,fileAlignment) * memAlignment; // ������Ҫ����һ��
		(pImageSectionHeader-1)->VirtualAddress = lastPointerRaw;
		(pImageSectionHeader-1)->SizeOfRawData = newSecSize;
		(pImageSectionHeader-1)->PointerToRawData = lastPointerFileRaw;
		(pImageSectionHeader-1)->Characteristics = pImageSectionHeader->Characteristics;
	}
	
	// �޸�PEͷImage�Ĵ�С
	if (is32bit) {
		PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((LONG64)fileHandle + peOffset);
		// �µ��ڴ��С
		pNtHeaders->OptionalHeader.SizeOfImage += addedMem;
	}else {
		PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((LONG64)fileHandle + peOffset);
		// �µ��ڴ��С
		pNtHeaders->OptionalHeader.SizeOfImage += addedMem;
	}
	// ���ص�ǰ��С
	return now_size;
}

/**
*	���ܣ�	���ӽڱ�
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬PPEStructure
*	����ֵ��
* PE�ļ�ͷ�еĽ���Ӧ�ñ��޸�
* PE��ѡͷ�еľ����СӦ�ñ��޸�
* PE��ѡͷ�е�checksum   MapFileAndCheckSum    #include<ImageHlp.h> #pragma comment(lib,"ImageHlp.lib")
* PE��ѡͷ�е�BASE OF CODE�п���Ҫ�޸�
*/
BOOL AddMemorySection(PVOID fileHandle, LONG peOffset, PIMAGE_SECTION_HEADER sectionHeader) {

}

// �ڲ���shellcode��PE�ļ�ʱ����Ӧ�ý�����ֱ�ӷŽ��������Ľ��У�
// 1. size of raw data < virtual size�Ľ��С������Ľ����������˴�����δ��ʼ����ȫ�ֱ����������ڴ��еĴ�СԶ�����ļ��еĴ�С�������жϽڵĿ������� 
/**
*	���ܣ�	��ָ��·�����ļ�
*   ������	PE�ļ��洢·��
*	����ֵ��PE�ļ�ӳ�����ڴ��ָ��
*/
PVOID OperatePeFile(const char* filePath, DWORD newSecSize, DWORD fileAlignment) {
	HANDLE fileHandle = NULL;
	LPVOID memFile = NULL;
	PLARGE_INTEGER fileSize = NULL;
	do {
		// ���ļ�
		fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		// ��ȡ�ļ���С
		fileSize = (PLARGE_INTEGER)malloc(sizeof(LARGE_INTEGER));
		if (!fileSize) {
			Log("��̬����洢�ļ���С�ı���ʧ��", "error", GetLastError());
			break;
		}
		memset(fileSize, 0x0, sizeof(LARGE_INTEGER));
		BOOL ok = GetFileSizeEx(fileHandle, fileSize);
		if (!ok) {
			Log("��ȡ�ļ�����ʧ��", "error", GetLastError());
			break;
		}
		LogData(filePath, "�ļ���С", "0x%x", fileSize->LowPart);
		// ��ǰ������½ڵĴ�С
		memFile = (LPVOID)malloc(fileSize->LowPart + (LONG64)newSecSize + fileAlignment);
		if (!memFile) {
			Log("�����ļ��ռ�ʧ��", "error", GetLastError());
			break;
		}
		// ��0
		memset(memFile, 0x0, fileSize->LowPart + (LONG64)newSecSize + fileAlignment);
		DWORD realRead = 0;
		// ReadFileһ������4GB���ļ�
		ok = ReadFile(fileHandle, memFile, fileSize->LowPart, &realRead, NULL);
		if (!ok || realRead != fileSize->LowPart) {
			Log("��ȡ�ļ�ʧ��", "error", GetLastError());
			free(memFile);
			break;
		}
	} while (FALSE);
	// �ͷ���Դ
	CloseHandle(fileHandle);
	free(fileSize);
	return memFile;
}

/**
*	���ܣ�	���ڴ�dump�ļ�������
*   ������	PE�ļ��洢·��, PE�ļ�ӳ�����ڴ��ָ��
*	����ֵ��
*/
VOID DumpPeFile(const char* filePath, PVOID fileHandle, DWORD fileSize) {
	HANDLE file = NULL;
	do {
		// �ɶ��򿪣������½����߸����ļ�
		file = CreateFileA(filePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		DWORD realWrite = 0;
		// �ļ���С�������һ���ڵ�Pointer To Raw Data + Size Of Raw Data
		BOOL ok = WriteFile(file, fileHandle, fileSize, &realWrite, NULL);
		if (!ok || realWrite != fileSize) {
			Log("д�ļ�ʧ��", "error", GetLastError());
			break;
		}
	} while (FALSE);
	// �ͷ���Դ
	CloseHandle(file);
}


/**
* ���ܣ� ����������������ض�λ������Ŀ¼��
* index ��0��ʼ
*/
VOID FixPeFile(PVOID fileHandle, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	DWORD rva = 0;
	PIMAGE_SECTION_HEADER pOrgImageSectionHeader = pImageSectionHeader;
	FixExport(fileHandle, peOffset, addedSize, index, peMainInfo, pOrgImageSectionHeader);
	FixImport(fileHandle, peOffset, addedSize, index, peMainInfo, pOrgImageSectionHeader);
	// ����ĿǰΪֹ���޸��ض�λ��û�������ù�
	FixBaseReloc(fileHandle, peOffset, addedSize, index, peMainInfo, pOrgImageSectionHeader);
	FixDataDirectory(fileHandle, peOffset, addedSize, index, peMainInfo, pOrgImageSectionHeader);
	FixResourceTable(fileHandle, peOffset, addedSize, index, peMainInfo, pOrgImageSectionHeader);
}
VOID FixExport(PVOID fileHandle, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	PIMAGE_DATA_DIRECTORY pExportDataDir = &peMainInfo->Export;
	if (pExportDataDir->VirtualAddress == 0) {
		LogExportTable("���������ڣ��ʲ���Ҫ�޸ĵ�����", "None");
		return 0;
	}
	// �������λ�ã�ֻ��һ�ŵ�����
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(RvaToFva2(fileHandle, peOffset, pExportDataDir->VirtualAddress, peMainInfo->Magic) + (LONG64)fileHandle);
	// ��ȡ���ź�����ر����Ϣ
	DWORD* funcAddressTable = (DWORD*)(RvaToFva2(fileHandle, peOffset, pExportTable->AddressOfFunctions, peMainInfo->Magic) + (LONG64)fileHandle); // ������ַ�� 
	DWORD* funcNameTable = (DWORD*)(RvaToFva2(fileHandle, peOffset, pExportTable->AddressOfNames, peMainInfo->Magic) + (LONG64)fileHandle); // �������Ʊ�
	WORD* funcNameOrdinalsTable = (WORD*)(RvaToFva2(fileHandle, peOffset, pExportTable->AddressOfNameOrdinals, peMainInfo->Magic) + (LONG64)fileHandle); // ��������˳���
	DWORD numberOfNames = pExportTable->NumberOfNames;
	DWORD numberOfFuncs = pExportTable->NumberOfFunctions;
	DWORD base = pExportTable->Base;
	// �޸ĵ������Ʊ��뵼����ַ���е�RVA
	for (DWORD i = 0; i < numberOfFuncs; i++) {
		if (funcAddressTable[i] == 0) {
			continue; // �յģ�Ҳ����˵�������Ǳ������˵�
		}
		DWORD j = 0;
		for (; j < numberOfNames; j++) {
			if (funcNameOrdinalsTable[j] == i) {
				// �޸ĺ�����ַ
				// ��ǰrva���޸ĺ�Ľڵĺ������Ҫ�ı�rva��ֵ
				if (FindSection(funcAddressTable[i], peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
					funcAddressTable[i] += addedSize;
				}
				// �޸ĺ������Ƶ�ַ
				if (FindSection(funcNameTable[j], peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
					funcNameTable[j] += addedSize;
				}
				break;
			}
		}
		if (j == numberOfNames) {
			// LogExportTable("��������", "NULL, ������� : %04x, ������ַ(RVA)�� %08x, �����ļ���ַ(FVA): %08I64x", ordinal, address, RvaToFva(fileHandle, peOffset, address));
			// �޸ĺ�����ַ
			if (FindSection(funcAddressTable[i], peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
				funcAddressTable[i] += addedSize;
			}
		}
	}
	// �޸ĵ������е�RVA
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
	// �޸����
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
		LogImportTable("���������,�ʲ���Ҫ�޸�", "None");
		return 0;
	}
	// ��ȡ��һ�ŵ����ĵ�ַ
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFva2(fileHandle, peOffset, pImportDataDir->VirtualAddress, peMainInfo->Magic) + (LONG64)fileHandle);
	while (pImportTable->Characteristics != 0) {
		LogImportTable("dll����", "%s", (PCHAR)(RvaToFva2(fileHandle, peOffset, pImportTable->Name, peMainInfo->Magic) + (LONG64)fileHandle));
		// LogImportTable("dll����", "%s", (PCHAR)(RvaToFva2(fileHandle, peOffset, (pImportTable+1)->Name, peMainInfo->Magic) + (LONG64)fileHandle));
		// ��ȡ����������
		if (FindSection(pImportTable->Name, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
			pImportTable->Name += addedSize;
		}
		// ����INT  pImportTable->OriginalFirstThunk => THUNK_DATA����
		LONG64 fva = RvaToFva2(fileHandle, peOffset, pImportTable->OriginalFirstThunk, peMainInfo->Magic);
		LONG64 fva2 = RvaToFva2(fileHandle, peOffset, pImportTable->FirstThunk, peMainInfo->Magic);
		if (is32bit) {
			PIMAGE_THUNK_DATA32 pImportNameTable = (PIMAGE_THUNK_DATA32)(fva + (LONG64)fileHandle);
			while (pImportNameTable->u1.Ordinal != 0) {
				// �ж����λ�Ƿ�Ϊ1
				if ((pImportNameTable->u1.Ordinal & 0x80000000) >> 31 != 1) {
					// �޸ĵ��뺯�����Ʊ�ĵ�ַ
					if (FindSection(pImportNameTable->u1.AddressOfData, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
						pImportNameTable->u1.AddressOfData += addedSize;
					}
				}
				// ��һ������
				pImportNameTable++;
				// �޸���һ���ֵ
			}
			// �޸�ÿһ�ű��OriginalFistThunk
			if (FindSection(pImportTable->OriginalFirstThunk, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
				pImportTable->OriginalFirstThunk += addedSize;
			}
		}else {
			PIMAGE_THUNK_DATA64 pImportNameTable = (PIMAGE_THUNK_DATA64)(fva + (LONG64)fileHandle);
			while (pImportNameTable->u1.Ordinal != 0) {
				// �ж����λ�Ƿ�Ϊ1
				if ((pImportNameTable->u1.Ordinal & 0x8000000000000000) >> 63 != 1) {
					// �޸ĵ��뺯�����Ʊ�ĵ�ַ
					if (FindSection(pImportNameTable->u1.AddressOfData, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
						pImportNameTable->u1.AddressOfData += addedSize;
					}
				}
				// ��һ������
				pImportNameTable++;
				// �޸���һ���ֵ
			}
			// �޸�ÿһ�ű��OriginalFistThunk
			if (FindSection(pImportTable->OriginalFirstThunk, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
				pImportTable->OriginalFirstThunk += addedSize;
			}
		}
		// Ŀǰ���������ļ���IAT��ֵ������INTһģһ��
		// �޸�IAT��������һ���ƺ����Ǻ��б�Ҫ����Ϊntoskrnl.exe�е�INT��IAT��ʹ���ļ����ƺ�Ҳ����һ��
		/**
		if (is32bit) {
			PIMAGE_THUNK_DATA32 pImportNameTable = (PIMAGE_THUNK_DATA32)(fva2 + (LONG64)fileHandle);
			while (pImportNameTable->u1.Ordinal != 0) {
				// �ж����λ�Ƿ�Ϊ1
				if ((pImportNameTable->u1.Ordinal & 0x80000000) >> 31 != 1) {
					// �޸ĵ��뺯�����Ʊ�ĵ�ַ
					if (FindSection(pImportNameTable->u1.AddressOfData, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
						pImportNameTable->u1.AddressOfData += addedSize;
					}
				}
				// ��һ������
				pImportNameTable++;
				// �޸���һ���ֵ
			}
			// �޸�ÿһ�ű��FistThunk
			if (FindSection(pImportTable->FirstThunk, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
				pImportTable->FirstThunk += addedSize;
			}
		}else {
			PIMAGE_THUNK_DATA64 pImportNameTable = (PIMAGE_THUNK_DATA64)(fva2 + (LONG64)fileHandle);
			while (pImportNameTable->u1.Ordinal != 0) {
				// �ж����λ�Ƿ�Ϊ1
				if ((pImportNameTable->u1.Ordinal & 0x8000000000000000) >> 63 != 1) {
					// �޸ĵ��뺯�����Ʊ�ĵ�ַ
					if (FindSection(pImportNameTable->u1.AddressOfData, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
						pImportNameTable->u1.AddressOfData += addedSize;
					}
				}
				// ��һ������
				pImportNameTable++;
				// �޸���һ���ֵ
			}
			// �޸�ÿһ�ű��FistThunk
			if (FindSection(pImportTable->FirstThunk, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
				pImportTable->FirstThunk += addedSize;
			}
		}
		*/
		// ��һ�ŵ����
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
		LogBaseRelocTable("�ض�λ������", "None");
		return 0;
	}
	PIMAGE_BASE_RELOCATION pBaseRelocTable = (PIMAGE_BASE_RELOCATION)(RvaToFva2(fileHandle, peOffset, pBaseRelocTableDir->VirtualAddress, peMainInfo->Magic) + (LONG64)fileHandle);
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
			// �ҵ�Ҫ�޸ĵ�Ӳ����
			PVOID changedAddr = (PVOID)(RvaToFva2(fileHandle, peOffset, baseRva + offset, peMainInfo->Magic) + (LONG64)fileHandle);
			// ֻ�и�λ��3���õ�ַ����Ҫ�ض�λ�������޸�
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
		// �޸Ļ���ֵ; ����������ֵ��Ӧ��ƫ��ǡ�ô����ڷָ��ߣ���ô���е����⣻
		if (FindSection(baseRva, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
			pBaseRelocTable->VirtualAddress += AddedDataLength(addedSize, 0x1000) * 0x1000;
		}
		LogBaseRelocTable("�ض�λ���޸ĺ��ַ", "0x%x", pBaseRelocTable->VirtualAddress);
		pBaseRelocTable = (PIMAGE_BASE_RELOCATION)((LONG64)pBaseRelocTable + pBaseRelocTable->SizeOfBlock);
	}
}
VOID FixDataDirectory(PVOID fileHandle, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	// ��ӡPE��ѡͷ�е�16�ű�������Ϣ
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
	// �������Ŀ¼��
	DWORD numberOfSecond = pResourceTableRoot->NumberOfIdEntries + pResourceTableRoot->NumberOfNamedEntries;
	// ������ʼ��λ��
	PIMAGE_RESOURCE_DIRECTORY_ENTRY firstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceTableRoot + 1);
	for (LONG64 i = 0; i < numberOfSecond; i++) {
		TraverseAndFixDirectory((LONG64)pResourceTableRoot, fileHandle, peOffset, addedSize, index, peMainInfo, firstEntry, 1, pImageSectionHeader);
		firstEntry++;
	}
}
VOID TraverseAndFixDirectory(PVOID fileHandle, PVOID fileHandle2, LONG peOffset, DWORD addedSize, DWORD index, POperatePeMainInfo peMainInfo, PIMAGE_RESOURCE_DIRECTORY_ENTRY nowEntry, DWORD level, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	if (nowEntry->DataIsDirectory) {
		PIMAGE_RESOURCE_DIRECTORY newEntry = (PIMAGE_RESOURCE_DIRECTORY)(nowEntry->OffsetToDirectory + (LONG64)fileHandle);
		// ��������Ŀ¼��
		DWORD numberOfSecond = newEntry->NumberOfIdEntries + newEntry->NumberOfNamedEntries;
		// ������ʼ��λ��
		PIMAGE_RESOURCE_DIRECTORY_ENTRY firstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(newEntry + 1);
		for (LONG64 i = 0; i < numberOfSecond; i++) {
			TraverseAndFixDirectory(fileHandle, fileHandle2, peOffset, addedSize, index, peMainInfo, firstEntry, level + 1, pImageSectionHeader);
			firstEntry++;
		}
	}else {
		// ��Դ�ļ�
		PIMAGE_RESOURCE_DATA_ENTRY newDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(nowEntry->OffsetToData + (LONG64)fileHandle);
		if (FindSection(newDataEntry->OffsetToData, peMainInfo->NumberOfSections, pImageSectionHeader) >= index) {
			newDataEntry->OffsetToData += addedSize;
		}
		// LogResource("��Դ�ļ�rva", level, "0x%x, ��Դ�ļ���С��0x%x", newDataEntry->OffsetToData, newDataEntry->Size);
	}
}

/**
* ���ܣ� ����һ��RVA��������������ĸ�������������:-1 0 1 2 3 4 ...��-1��ζ�������ᷢ���ı䣨�����ڵ�һ����֮ǰ��
*/
LONG64 FindSection(DWORD rva, DWORD numberOfSections, PIMAGE_SECTION_HEADER pImageSectionHeader) {
	// RVA�ڵ�һ����֮ǰ������-1;��Ϊ���е����Ӳ����Ǵӽ�ͷ��֮��ʼ���еġ�
	if (rva < pImageSectionHeader->PointerToRawData) {
		return -1;
	}
	LONG64 count = 0;
	for (count = 0; count < numberOfSections; count++) {
		// �������ƫ��
		LONG64 baseSection = pImageSectionHeader->VirtualAddress;
		LONG64 virtualSize = pImageSectionHeader->Misc.VirtualSize;
		LONG64 baseFileSection = pImageSectionHeader->PointerToRawData;
		// �ҵ���Ӧ��
		if (rva >= baseSection && rva <= baseSection + virtualSize) {
			if (count < numberOfSections - 1 && rva == (pImageSectionHeader + 1)->VirtualAddress) {
				count++;
			}
			break;
		}
		pImageSectionHeader++;
	}
	if (count >= numberOfSections) {
		Log("δ��λ����Ӧ��RVA��ַ","Warning",0);
	}
	return count;
}

// ����ĳ����

// ���ļ������Ϊ���ڴ����һ��

// �޸�IAT

// ͨ���ض�λ������ض�λ����



/**
*	���ܣ�	RVA to FVA
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬RVA
*	����ֵ��FVA
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
		// peͷ
		PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((LONG64)fileHandle + peOffset);
		// PE�ļ�ͷ
		PIMAGE_FILE_HEADER pNtFileHeader = &pNtHeaders->FileHeader;
		// PE��ѡͷ
		PIMAGE_OPTIONAL_HEADER32 pNtOpHeader = &pNtHeaders->OptionalHeader;
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
			PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LONG64)fileHandle + peOffset + sizeof(IMAGE_NT_HEADERS32));
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
					break;
				}
				pImageSectionHeader++;
			}
		}
		return fva;
	}else {
		// peͷ
		PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((LONG64)fileHandle + peOffset);
		// PE�ļ�ͷ
		PIMAGE_FILE_HEADER pNtFileHeader = &pNtHeaders->FileHeader;
		// PE��ѡͷ
		PIMAGE_OPTIONAL_HEADER64 pNtOpHeader = &pNtHeaders->OptionalHeader;
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
			PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LONG64)fileHandle + peOffset + sizeof(IMAGE_NT_HEADERS64));
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
					break;
				}
				pImageSectionHeader++;
			}
		}
		return fva;
	}
}