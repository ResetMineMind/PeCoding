#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdio.h>

/**
* ����Ŀ��2023��7��18����������Ŀ��������ϤPE�ṹ���������ģ��Ӧ������
*	1. ����PE�ļ���������
*	2. ����һ�����԰�������PE�ļ��Ľṹ��
*	3. Ϊ��������������������ṩ����
*	4. Ϊ�������ӽ��ṩ����
*	5. Ϊ��������ӿǡ��ѿ��ṩ����
*	6. ��ɶ�IAT���ض�λ����޸�
*	7. Ϊ���������ֶ�ӳ���ṩ����
*	8. ����Ϊ����PE�ļ��ĸ����ֽ��ṩ����
*/ 

#if TYPE == 0
#define x86_PROGRAM 32
#else
#define x64_PROGRAM 64
#endif

typedef struct _PeNtFileHeaderData {
	// ��������
	WORD NumberOfSections;
	// �������ж��Ƿ�Ϊdll/exe
	WORD Characteristics;
	// ��ѡͷ��С
	WORD SizeOfOptionalHeader;
}PeNtFileHeaderData,*PPeNtFileHeaderData;

typedef struct _PeNtOptionalHeaderData32 {
	// 32/64λ����
	WORD Magic;
	// ������ڵ��RVA
	DWORD AddressOfEntryPoint;
	// �������ʼRVA
	DWORD BaseOfCode;
	// �����Ĵ�С
	DWORD SizeOfCode;  // �ļ�����Ĵ�С
	// ���ݿ���ʼRVA
	DWORD BaseOfData;
	// Ԥ���ڴ��ַ
	DWORD ImageBase;
	// �ڴ����
	DWORD SectionAlignment;
	// �ļ�����
	DWORD FileAlignment;
	// �����С
	DWORD SizeOfImage; // �ڴ������ļ��ܴ�С
	// ͷ����С
	DWORD SizeOfHeaders; // �ļ�����Ľ�ǰͷ����С
	// ������
	IMAGE_DATA_DIRECTORY Export;
	// ����� 
	IMAGE_DATA_DIRECTORY Import;
	// IAT
	IMAGE_DATA_DIRECTORY IAT;
	// �ض�λ��
	IMAGE_DATA_DIRECTORY BaseReloc;
}PeNtOptionalHeaderData32, * PPeNtOptionalHeaderData32;
typedef struct _PeNtOptionalHeaderData64 {
	// 32/64λ����
	WORD Magic;
	// ������ڵ��RVA
	DWORD AddressOfEntryPoint;
	// �������ʼRVA
	DWORD BaseOfCode;
	// �����Ĵ�С
	DWORD SizeOfCode;  // �ļ�����Ĵ�С
	// ���ݿ���ʼRVA
	DWORD BaseOfData;
	// Ԥ���ڴ��ַ
	ULONGLONG ImageBase;
	// �ڴ����
	DWORD SectionAlignment;
	// �ļ�����
	DWORD FileAlignment;
	// �����С
	DWORD SizeOfImage; // �ڴ������ļ��ܴ�С
	// ͷ����С
	DWORD SizeOfHeaders; // �ļ�����Ľ�ǰͷ����С
	// ������
	IMAGE_DATA_DIRECTORY Export;
	// ����� 
	IMAGE_DATA_DIRECTORY Import;
	// IAT
	IMAGE_DATA_DIRECTORY IAT;
	// �ض�λ��
	IMAGE_DATA_DIRECTORY BaseReloc;
}PeNtOptionalHeaderData64, * PPeNtOptionalHeaderData64;

#ifdef x86_PROGRAM
typedef struct _x86PEStructure {
	// NT�ļ�ͷ�����Ϣ
	PPeNtFileHeaderData pPeNtFileData;
	// NT��ѡͷ�ļ���С
	PPeNtOptionalHeaderData32 pPeNtOptionalData;
	// ��һ���ڱ�ͷ��ʼλ��
	PIMAGE_SECTION_HEADER pImageSectionHeader;
}x86PEStructure, * Px86PEStructure;

#define PPEStructure Px86PEStructure
#define PEStructure x86PEStructure
#define PMYIMAGE_NT_HEADERS PIMAGE_NT_HEADERS32
#define MYIMAGE_NT_HEADERS IMAGE_NT_HEADERS32
#define PMYIMAGE_OPTIONAL_HEADER PIMAGE_OPTIONAL_HEADER32
#define PeNtOptionalHeaderData PeNtOptionalHeaderData32
#define PPeNtOptionalHeaderData PPeNtOptionalHeaderData32
#define PMYIMAGE_THUNK_DATA PIMAGE_THUNK_DATA32
#endif

#ifdef x64_PROGRAM
typedef struct _x64PEStructure {
	// NT�ļ�ͷ�����Ϣ
	PPeNtFileHeaderData pPeNtFileData;
	// NT��ѡͷ�ļ���С
	PPeNtOptionalHeaderData64 pPeNtOptionalData;
	// ��һ���ڱ�ͷ��ʼλ��
	PIMAGE_SECTION_HEADER pImageSectionHeader;
}x64PEStructure, * Px64PEStructure;

#define PPEStructure Px64PEStructure
#define PEStructure x64PEStructure
#define PMYIMAGE_NT_HEADERS PIMAGE_NT_HEADERS64
#define MYIMAGE_NT_HEADERS IMAGE_NT_HEADERS64
#define PMYIMAGE_OPTIONAL_HEADER PIMAGE_OPTIONAL_HEADER64
#define PeNtOptionalHeaderData PeNtOptionalHeaderData64
#define PPeNtOptionalHeaderData PPeNtOptionalHeaderData64
#define PMYIMAGE_THUNK_DATA PIMAGE_THUNK_DATA64
#endif


/*********************************************************************************************************
*                                           ���õ���־��¼                                               *
**********************************************************************************************************/
#define Log(msg, type, errCode) {printf("[%s]: %s��������: 0x%x\n", type, msg, errCode);}
#define LogData(file, characteristic, how_type, ...) {printf("[info] %s��%s: "how_type" \n", file, characteristic, __VA_ARGS__);}
// ���ڴ�ӡDOSͷ��Ϣ
#define LogDosHeader(mark, how_type, ...) {printf("[----DosHeader----] %s : "how_type" \n", mark, __VA_ARGS__);}
// ���ڴ�ӡNTͷ��Ϣ
#define LogNtHeader(mark, how_type, ...) {printf("[----NtHeader-----]  %s : "how_type" \n", mark, __VA_ARGS__);}
// ���ڴ�ӡ�ڱ�ͷ��Ϣ
#define LogSecHeader(mark, how_type, ...) {printf("[--SectionHeader--]  %s : "how_type" \n", mark, __VA_ARGS__);}
// ���ڴ�ӡ���ŵ�������Ϣ
#define LogImportTable(mark, how_type, ...) {printf("[---ImportTable---]  %s : "how_type" \n", mark, __VA_ARGS__);}
// ���ڴ�ӡ���������Ϣ
#define LogExportTable(mark, how_type, ...) {printf("[---ExportTable---]  %s : "how_type" \n", mark, __VA_ARGS__);}
// �ָ���
#define SplitLine() {printf("\n********************************************************************************\n\n");}

/*********************************************************************************************************
*                                             �Զ��庯��                                                 *
**********************************************************************************************************/

/**
*	���ܣ�	��ָ��·�����ļ�
*   ������	PE�ļ��洢·��
*	����ֵ��PE�ļ�ӳ�����ڴ��ָ��
*/
PVOID OpenPeFile(const char* filePath);

/**
*	���ܣ�	��ӡDOSͷ�����Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ��
*	����ֵ��PEͷ��ƫ��
*/
LONG AnalyzeDosHeader(PVOID fileHandle);

/**
*	���ܣ�	��ӡ32/64λPE�ļ���PEͷ�����Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ��
*	����ֵ������PEStructure��
*/
PPEStructure AnalyzeNtHeader(PVOID fileHandle, LONG peOffset);

/**
*	���ܣ�	��ӡ32/64λPE�ļ��Ľڱ������Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ�ƣ�PPEStructure�ṹ��
*	����ֵ��
*/
LONG64 AnalyzeSectionHeader(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure);

/**
*	���ܣ�	����32/64λPE�ļ��ĵ���������Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ�ƣ�PPEStructure�ṹ��
*	����ֵ��
*/
LONG64 AnalyzeImportTable(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure);

/**
*	���ܣ�	����32/64λPE�ļ��ĵ����������Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ�ƣ�PPEStructure�ṹ��
*	����ֵ��
*/
LONG64 AnalyzeExportTable(PVOID fileHandle, LONG peOffset, PPEStructure pPeStructure);

/**
*	���ܣ�	RVA to FVA
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬RVA
*	����ֵ��FVA
*/
LONG64 RvaToFva(PVOID fileHandle, LONG peOffset, LONG64 rva);

/**
*	���ܣ�	�жϵ�ǰ�ļ���λ��
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ��
*	����ֵ��
*/
VOID JudgeFile(PVOID fileHandle, LONG peOffset);