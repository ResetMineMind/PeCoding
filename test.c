#define TYPE 1 // 0 =>32  1 =>64 // ����������Ļ����ᵼ��test.c��ʹ�õ�PPEStructure �� peAnalyze.c�е�PPEStructure��Ӧ�ĺ겻ͬ
#include "pe.h"

int main() {
	PVOID fileHandle = OpenPeFile("C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x64_bak.exe");
	if (!fileHandle) {
		Log("ӳ��PE�ļ�ʧ��", "error", GetLastError());
		return -1;
	}
	LogData("C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x64_bak.exe", "�ڴ���ӳ���ַ", "0x%p", fileHandle);
	// ����Dosͷ
	LONG peOffset = AnalyzeDosHeader(fileHandle);
	// ����NTͷ
	PPEStructure pPeStructure = AnalyzeNtHeader(fileHandle, peOffset);
	if (!pPeStructure) {
		Log("ΪPEͷ�ؼ���Ϣ����ռ�ʧ��", "error", GetLastError());
		return -1;
	}
	// �����ڱ�ͷ
	AnalyzeSectionHeader(fileHandle, peOffset, pPeStructure);
	// ���������
	AnalyzeImportTable(fileHandle, peOffset, pPeStructure);
	// ����������
	AnalyzeExportTable(fileHandle, peOffset, pPeStructure);
	// �ر�ֻ���ļ�
	UnmapViewOfFile(fileHandle);
	//-------------------------------------------------------------------------
	// ��дȨ�����´��ļ�
	PVOID fileWriteHandle = OperatePeFile("C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x64_bak.exe", 0x2000, pPeStructure->pPeNtOptionalData->FileAlignment);
	if (!fileWriteHandle) {
		Log("ӳ��PE�ļ�ʧ��", "error", GetLastError());
		return -1;
	}
	LogData("C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x64_bak.exe", "�ڴ���ӳ���ַ", "0x%p", fileWriteHandle);
	OperatePeMainInfo peMainInfo;
	peMainInfo.BaseReloc = pPeStructure->pPeNtOptionalData->BaseReloc;
	peMainInfo.Export = pPeStructure->pPeNtOptionalData->Export;
	peMainInfo.Import = pPeStructure->pPeNtOptionalData->Import;
	peMainInfo.Magic = pPeStructure->pPeNtOptionalData->Magic;
	peMainInfo.NumberOfSections = pPeStructure->pPeNtFileData->NumberOfSections;
	peMainInfo.SectionHeader = pPeStructure->SectionHeader;
	peMainInfo.DataDir = pPeStructure->pPeNtOptionalData->DataDir;
	// ����IAT
	FillTheIAT(fileWriteHandle, peOffset, &peMainInfo);
	// ����һ����
	DWORD now_size = AddFileSection(fileWriteHandle, peOffset, &peMainInfo, 6, 0x1001);
	// ���ļ�dump����
	DumpPeFile("C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x64_bak2.exe", fileWriteHandle, now_size);
	// �ͷ���Դ
	free(pPeStructure->pPeNtFileData);
	free(pPeStructure->pPeNtOptionalData);
	free(pPeStructure->pSectionGaps);
	free(pPeStructure);
}