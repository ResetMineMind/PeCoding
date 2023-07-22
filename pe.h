#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdio.h>

/**
* 本项目于2023年7月18日启动，其目的在于熟悉PE结构，任务完成模块应包括：
*	1. 解析PE文件基本内容
*	2. 构建一个可以包含整个PE文件的结构体
*	3. 为后续操作导入表、导出表提供便利
*	4. 为后续增加节提供便利
*	5. 为后续程序加壳、脱壳提供便利
*	6. 完成对IAT和重定位表的修复
*	7. 为后续程序手动映射提供便利
*	8. 整体为操作PE文件的各个字节提供便利
*/ 
typedef struct _PeNtFileHeaderData {
	// 节区数量
	WORD NumberOfSections;
	// 可用于判断是否为dll/exe
	WORD Characteristics;
	// 可选头大小
	WORD SizeOfOptionalHeader;
}PeNtFileHeaderData,*PPeNtFileHeaderData;

typedef struct _PeNtOptionalHeaderData32 {
	// 32/64位程序
	WORD Magic;
	// 代码入口点的RVA
	DWORD AddressOfEntryPoint;
	// 代码块起始RVA
	DWORD BaseOfCode;
	// 代码块的大小
	DWORD SizeOfCode;  // 文件对齐的大小
	// 数据块起始RVA
	DWORD BaseOfData;
	// 预期内存地址
	DWORD ImageBase;
	// 内存对齐
	DWORD SectionAlignment;
	// 文件对齐
	DWORD FileAlignment;
	// 镜像大小
	DWORD SizeOfImage; // 内存对齐的文件总大小
	// 头部大小
	DWORD SizeOfHeaders; // 文件对齐的节前头部大小
	// 导出表
	IMAGE_DATA_DIRECTORY Export;
	// 导入表 
	IMAGE_DATA_DIRECTORY Import;
	// IAT
	IMAGE_DATA_DIRECTORY IAT;
	// 重定位表
	IMAGE_DATA_DIRECTORY BaseReloc;
}PeNtOptionalHeaderData32, * PPeNtOptionalHeaderData32;

typedef struct _x86PEStructure {
	// NT文件头相关信息
	PPeNtFileHeaderData pPeNtFileData;
	// NT可选头文件大小
	PPeNtOptionalHeaderData32 pPeNtOptionalData;
	// 第一个节表头起始位置
	PIMAGE_SECTION_HEADER pImageSectionHeader;

}x86PEStructure, * Px86PEStructure;

typedef struct _x64PEStructure {
	// NT文件头相关信息
	PPeNtFileHeaderData pPeNtFileData;
}x64PEStructure, * Px64PEStructure;

/*********************************************************************************************************
*                                           良好的日志记录                                               *
**********************************************************************************************************/
#define Log(msg, type, errCode) {printf("[%s]: %s，错误码: 0x%x\n", type, msg, errCode);}
#define LogData(file, characteristic, how_type, ...) {printf("[info] %s的%s: "how_type"\n", file, characteristic, __VA_ARGS__);}
// 用于打印DOS头信息
#define LogDosHeader(mark, how_type, ...) {printf("[----DosHeader----] %s : "how_type"\n", mark, __VA_ARGS__);}
// 用于打印NT头信息
#define LogNtHeader(mark, how_type, ...) {printf("[----NtHeader-----]  %s : "how_type"\n", mark, __VA_ARGS__);}
// 用于打印节表头信息
#define LogSecHeader(mark, how_type, ...) {printf("[--SectionHeader--]  %s : "how_type"\n", mark, __VA_ARGS__);}
// 用于打印各张导入表的信息
#define LogImportTable(mark, how_type, ...) {printf("[---ImportTable---]  %s : "how_type"\n", mark, __VA_ARGS__);}
// 用于打印导出表的信息
#define LogExportTable(mark, how_type, ...) {printf("[---ExportTable---]  %s : "how_type"\n", mark, __VA_ARGS__);}
// 分割线
#define SplitLine() {printf("\n********************************************************************************\n\n");}

/*********************************************************************************************************
*                                             自定义函数                                                 *
**********************************************************************************************************/

/**
*	功能：	打开指定路径的文件
*   参数：	PE文件存储路径
*	返回值：PE文件映射至内存的指针
*/
PVOID OpenPeFile(const char* filePath);

/**
*	功能：	打印DOS头相关信息
*   参数：	PE文件映射至内存的指针
*	返回值：PE头的偏移
*/
LONG AnalyzeDosHeader(PVOID fileHandle);

/**
*	功能：	打印32位PE文件的PE头相关信息
*   参数：	PE文件映射至内存的指针，偏移
*	返回值：构建PEStructure。
*/
Px86PEStructure AnalyzeNtHeader32(PVOID fileHandle, LONG peOffset);

/**
*	功能：	打印32位PE文件的节表相关信息
*   参数：	PE文件映射至内存的指针，偏移
*	返回值：
*/
LONG AnalyzeSectionHeader(PVOID fileHandle, LONG peOffset, Px86PEStructure pPeStructure);

/**
*	功能：	解析32位PE文件的导入表相关信息
*   参数：	Px86PEStructure结构体
*	返回值：
*/
LONG AnalyzeImportTable(PVOID fileHandle, LONG peOffset, Px86PEStructure pPeStructure);

/**
*	功能：	解析32位PE文件的导出表相关信息
*   参数：	PE文件映射至内存的指针，偏移
*	返回值：
*/
LONG AnalyzeExportTable(PVOID fileHandle, LONG peOffset, Px86PEStructure pPeStructure);

/**
*	功能：	RVA to FVA
*   参数：	PE文件映射至内存的指针，RVA，Px86PEStructure
*	返回值：FVA
*/
DWORD RvaToFva(PVOID fileHandle, LONG peOffset, DWORD rva);
