#define TYPE 1 // 0 =>32  1 =>64 // 不设置这个的话，会导致test.c中使用的PPEStructure 与 peAnalyze.c中的PPEStructure对应的宏不同
#include "pe.h"
#define path1 "C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x64_bak.exe"
#define path2 "C:\\Users\\xuji\\Desktop\\PeCoding\\cmd_x64_bak2.exe"

int main() {
	PVOID fileHandle = OpenPeFile(path1);
	if (!fileHandle) {
		Log("映射PE文件失败", "error", GetLastError());
		return -1;
	}
	LogData("path1", "内存中映射地址", "0x%p", fileHandle);
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
	// 解析重定位表
	AnalyzeBaseRelocTable(fileHandle, peOffset, pPeStructure);
	// 解析资源
	AnalyzeResourceTable(fileHandle, peOffset, pPeStructure);
	// 关闭只读文件
	UnmapViewOfFile(fileHandle);
	//-------------------------------------------------------------------------
	// 读写权限重新打开文件
	PVOID fileWriteHandle = OperatePeFile(path1, 0x2000, pPeStructure->pPeNtOptionalData->FileAlignment);
	if (!fileWriteHandle) {
		Log("映射PE文件失败", "error", GetLastError());
		return -1;
	}
	LogData(path1, "内存中映射地址", "0x%p", fileWriteHandle);
	OperatePeMainInfo peMainInfo;
	peMainInfo.BaseReloc = pPeStructure->pPeNtOptionalData->BaseReloc;
	peMainInfo.Export = pPeStructure->pPeNtOptionalData->Export;
	peMainInfo.Import = pPeStructure->pPeNtOptionalData->Import;
	peMainInfo.Magic = pPeStructure->pPeNtOptionalData->Magic;
	peMainInfo.NumberOfSections = pPeStructure->pPeNtFileData->NumberOfSections;
	peMainInfo.SectionHeader = pPeStructure->SectionHeader;
	peMainInfo.DataDir = pPeStructure->pPeNtOptionalData->DataDir;
	peMainInfo.ImageBase = pPeStructure->pPeNtOptionalData->ImageBase;
	peMainInfo.Resource = pPeStructure->pPeNtOptionalData->Resource;
	// 看看IAT
	FillTheIAT(fileWriteHandle, peOffset, &peMainInfo);
	// 增加一个节
	DWORD now_size = AddFileSection(fileWriteHandle, peOffset, &peMainInfo, 6, 0x1001);
	// 将文件dump下来
	DumpPeFile(path2, fileWriteHandle, now_size);
	// 释放资源
	free(pPeStructure->pPeNtFileData);
	free(pPeStructure->pPeNtOptionalData);
	free(pPeStructure->pSectionGaps);
	free(pPeStructure);
}