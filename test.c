#include "pe.h"


int main() {
	PVOID fileHandle = OpenPeFile("C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x86.exe");
	if (!fileHandle) {
		Log("ӳ��PE�ļ�ʧ��", "error", GetLastError());
		return -1;
	}
	LogData("C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x86.exe", "�ڴ���ӳ���ַ", "0x%p", fileHandle);
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
	// �ͷ���Դ
	free(pPeStructure->pPeNtFileData);
	free(pPeStructure->pPeNtOptionalData);
	free(pPeStructure);
}