#include "pe.h"


int main() {
	PVOID fileHandle = OpenPeFile("C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x86.exe");
	if (!fileHandle) {
		Log("映射PE文件失败", "error", GetLastError());
		return -1;
	}
	LogData("C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x86.exe", "内存中映射地址", "0x%p", fileHandle);
	// 解析Dos头
	LONG peOffset = AnalyzeDosHeader(fileHandle);
	// 解析NT头
	PPEStructure pPeStructure = AnalyzeNtHeader(fileHandle, peOffset);
	if (!pPeStructure) {
		Log("为PE头关键信息分配空间失败", "error", GetLastError());
		return -1;
	}
	// 解析节表头
	AnalyzeSectionHeader(fileHandle, peOffset, pPeStructure);
	// 解析导入表
	AnalyzeImportTable(fileHandle, peOffset, pPeStructure);
	// 解析导出表
	AnalyzeExportTable(fileHandle, peOffset, pPeStructure);
	// 释放资源
	free(pPeStructure->pPeNtFileData);
	free(pPeStructure->pPeNtOptionalData);
	free(pPeStructure);
}