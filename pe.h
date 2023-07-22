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

typedef struct _x86PEStructure {
	// NT�ļ�ͷ�����Ϣ
	PPeNtFileHeaderData pPeNtFileData;
	// NT��ѡͷ�ļ���С
	PPeNtOptionalHeaderData32 pPeNtOptionalData;
	// ��һ���ڱ�ͷ��ʼλ��
	PIMAGE_SECTION_HEADER pImageSectionHeader;

}x86PEStructure, * Px86PEStructure;

typedef struct _x64PEStructure {
	// NT�ļ�ͷ�����Ϣ
	PPeNtFileHeaderData pPeNtFileData;
}x64PEStructure, * Px64PEStructure;

/*********************************************************************************************************
*                                           ���õ���־��¼                                               *
**********************************************************************************************************/
#define Log(msg, type, errCode) {printf("[%s]: %s��������: 0x%x\n", type, msg, errCode);}
#define LogData(file, characteristic, how_type, ...) {printf("[info] %s��%s: "how_type"\n", file, characteristic, __VA_ARGS__);}
// ���ڴ�ӡDOSͷ��Ϣ
#define LogDosHeader(mark, how_type, ...) {printf("[----DosHeader----] %s : "how_type"\n", mark, __VA_ARGS__);}
// ���ڴ�ӡNTͷ��Ϣ
#define LogNtHeader(mark, how_type, ...) {printf("[----NtHeader-----]  %s : "how_type"\n", mark, __VA_ARGS__);}
// ���ڴ�ӡ�ڱ�ͷ��Ϣ
#define LogSecHeader(mark, how_type, ...) {printf("[--SectionHeader--]  %s : "how_type"\n", mark, __VA_ARGS__);}
// ���ڴ�ӡ���ŵ�������Ϣ
#define LogImportTable(mark, how_type, ...) {printf("[---ImportTable---]  %s : "how_type"\n", mark, __VA_ARGS__);}
// ���ڴ�ӡ���������Ϣ
#define LogExportTable(mark, how_type, ...) {printf("[---ExportTable---]  %s : "how_type"\n", mark, __VA_ARGS__);}
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
*	���ܣ�	��ӡ32λPE�ļ���PEͷ�����Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ��
*	����ֵ������PEStructure��
*/
Px86PEStructure AnalyzeNtHeader32(PVOID fileHandle, LONG peOffset);

/**
*	���ܣ�	��ӡ32λPE�ļ��Ľڱ������Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ��
*	����ֵ��
*/
LONG AnalyzeSectionHeader(PVOID fileHandle, LONG peOffset, Px86PEStructure pPeStructure);

/**
*	���ܣ�	����32λPE�ļ��ĵ���������Ϣ
*   ������	Px86PEStructure�ṹ��
*	����ֵ��
*/
LONG AnalyzeImportTable(PVOID fileHandle, LONG peOffset, Px86PEStructure pPeStructure);

/**
*	���ܣ�	����32λPE�ļ��ĵ����������Ϣ
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬ƫ��
*	����ֵ��
*/
LONG AnalyzeExportTable(PVOID fileHandle, LONG peOffset, Px86PEStructure pPeStructure);

/**
*	���ܣ�	RVA to FVA
*   ������	PE�ļ�ӳ�����ڴ��ָ�룬RVA��Px86PEStructure
*	����ֵ��FVA
*/
DWORD RvaToFva(PVOID fileHandle, LONG peOffset, DWORD rva);
