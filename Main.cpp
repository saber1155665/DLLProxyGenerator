#include <iostream>
#include <Windows.h>
#include <Commdlg.h>
#include <String.h>
#include <winnt.h>
#include <imagehlp.h>
#include <vector>
#include <string>
#include <fstream>
#include <tchar.h>
#include <stdio.h>

using namespace std;

// Check if its 32bit or 64bit
WORD fileType;

// Exported names
vector<string> names;

std::vector<std::string> explode(const std::string &s, const char &c)
{
    // 替换C++11的初始化方式为传统方式
    std::string buff = "";
    std::vector<std::string> v;

    // 替换C++11范围for循环为传统迭代器循环（VS2010支持）
    for (std::string::const_iterator it = s.begin(); it != s.end(); ++it)
    {
        char n = *it; // 解引用迭代器获取当前字符
        if (n != c)
            buff += n;
        else if (n == c && buff != "")
        {
            v.push_back(buff);
            buff = "";
        }
    }
    if (buff != "")
        v.push_back(buff);

    return v;
}

// ===================== 基础函数封装（关闭/恢复重定向） =====================
/**
 * @brief 关闭WOW64文件系统重定向
 * @param pOldValue [out] 保存重定向上下文，用于后续恢复
 * @return 成功返回TRUE，失败返回FALSE
 */
BOOL DisableWow64Redirection(PVOID* pOldValue)
{
    // 函数指针类型（兼容不同Windows版本）
    typedef BOOL (WINAPI* PFN_Wow64DisableWow64FsRedirection)(PVOID*);
    
    // 动态获取函数地址（避免老系统无此函数导致编译/运行错误）
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return FALSE;
    }

    PFN_Wow64DisableWow64FsRedirection pFunc = 
        (PFN_Wow64DisableWow64FsRedirection)GetProcAddress(hKernel32, "Wow64DisableWow64FsRedirection");
    
    if (!pFunc)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    // 调用关闭重定向函数
    return pFunc(pOldValue);
}

/**
 * @brief 恢复WOW64文件系统重定向
 * @param pOldValue [in] 关闭重定向时保存的上下文
 * @return 成功返回TRUE，失败返回FALSE
 */
BOOL RevertWow64Redirection(PVOID pOldValue)
{
    // 函数指针类型
    typedef BOOL (WINAPI* PFN_Wow64RevertWow64FsRedirection)(PVOID);
    
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return FALSE;
    }

    PFN_Wow64RevertWow64FsRedirection pFunc = 
        (PFN_Wow64RevertWow64FsRedirection)GetProcAddress(hKernel32, "Wow64RevertWow64FsRedirection");
    
    if (!pFunc)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    // 调用恢复重定向函数
    return pFunc(pOldValue);
}
// ===================== RAII封装（自动恢复重定向，避免泄漏） =====================
/**
 * @brief RAII封装类：构造时关闭重定向，析构时自动恢复
 * （VS2010支持C++03，该封装无语法问题）
 */
class Wow64RedirectionGuard
{
private:
    PVOID m_oldValue;  // 重定向上下文
    BOOL m_bDisabled;  // 是否成功关闭了重定向

public:
    // 构造函数：自动关闭重定向
    Wow64RedirectionGuard() : m_oldValue(NULL), m_bDisabled(FALSE)
    {
        m_bDisabled = DisableWow64Redirection(&m_oldValue);
        if (!m_bDisabled)
        {
            DWORD dwErr = GetLastError();
            std::cerr << "关闭WOW64重定向失败，错误码：" << dwErr << std::endl;
        }
    }

    // 析构函数：自动恢复重定向（无论是否成功关闭，都尝试恢复）
    ~Wow64RedirectionGuard()
    {
        if (m_bDisabled)
        {
            if (!RevertWow64Redirection(m_oldValue))
            {
                DWORD dwErr = GetLastError();
                std::cerr << "恢复WOW64重定向失败，错误码：" << dwErr << std::endl;
            }
        }
    }



    // 判断是否成功关闭重定向
    BOOL IsDisabled() const { return m_bDisabled; }

private:
	// 禁止拷贝（避免重复恢复）
    Wow64RedirectionGuard(const Wow64RedirectionGuard&);
    Wow64RedirectionGuard& operator=(const Wow64RedirectionGuard&);
};

bool getImageFileHeaders(string fileName, IMAGE_NT_HEADERS &headers)
{
	Wow64RedirectionGuard guard;  // 构造时自动关闭重定向

	std::wstring wFileName = std::wstring(fileName.begin(), fileName.end());
	HANDLE fileHandle = CreateFile(
        wFileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);
	if (fileHandle == INVALID_HANDLE_VALUE)
		return false;

	HANDLE imageHandle = CreateFileMapping(
		fileHandle,
		nullptr,
		PAGE_READONLY,
		0,
		0,
		nullptr);
	if (imageHandle == 0)
	{
		CloseHandle(fileHandle);
		return false;
	}

	void *imagePtr = MapViewOfFile(
		imageHandle,
		FILE_MAP_READ,
		0,
		0,
		0);
	if (imagePtr == nullptr)
	{
		CloseHandle(imageHandle);
		CloseHandle(fileHandle);
		return false;
	}

	PIMAGE_NT_HEADERS headersPtr = ImageNtHeader(imagePtr);
	if (headersPtr == nullptr)
	{
		UnmapViewOfFile(imagePtr);
		CloseHandle(imageHandle);
		CloseHandle(fileHandle);
		return false;
	}

	headers = *headersPtr;

	UnmapViewOfFile(imagePtr);
	CloseHandle(imageHandle);
	CloseHandle(fileHandle);

	return true;
}

void listDLLFunctions(string sADllName, vector<string> &slListOfDllFunctions)
{
	DWORD *dNameRVAs(0);
	DWORD *dNameRVAs2(0);
	_IMAGE_EXPORT_DIRECTORY *ImageExportDirectory;
	unsigned long cDirSize;
	_LOADED_IMAGE LoadedImage;
	string sName;
	slListOfDllFunctions.clear();
	if (MapAndLoad(sADllName.c_str(), NULL, &LoadedImage, TRUE, TRUE))
	{
		ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY *)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

		if (ImageExportDirectory != NULL)
		{
			dNameRVAs = (DWORD *)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);

			for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++)
			{
				sName = (char *)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);
				slListOfDllFunctions.push_back(sName);
			}
		}
		UnMapAndLoad(&LoadedImage);
	}
}

void generateDEF(string name, vector<string> names)
{
	std::fstream file;
	file.open(name + ".def", std::ios::out);
	file << "LIBRARY " << name << endl;
	file << "EXPORTS" << endl;

	// Loop them
	for (int i = 0; i < names.size(); i++)
	{
		file << "\t" << names[i] << "=Fake" << names[i] << i << " @" << i + 1 << endl;
	}

	file.close();
}

void generateMainCPP(string name, vector<string> names)
{
	size_t fileNameLength = name.size() + 6;
	std::fstream file;
	file.open(name + ".cpp", std::ios::out);
	file << "#include <windows.h>" << endl
		<< "#include <tchar.h>" << endl
		<< "#include <strsafe.h>" << endl
		 << endl;
	file << "extern \"C\" void LoadProc();"<< std::endl;
	file << "extern \"C\"void* g_p"<< name << ";" << std::endl;

	file << "struct " << name << "_dll { \n"
		 << "\tHMODULE dll;\n";

	for (int i = 0; i < names.size(); i++)
	{
		file << "\tFARPROC Orignal" << names[i] << ";\n";
	}
	file << "} " << name << ";\n\n";

	file << "void *g_p"<< name << " = &"<< name <<";" <<   std::endl;

	{ //x86
		file << "#if defined(WIN64_) \n"<< std::endl;
		file << "#else \n"<< std::endl;
		for (int i = 0; i < names.size(); i++)
		{
			file << "__declspec(naked) void Fake" << names[i] << i << "() { _asm { call LoadProc; \n \t\t\t jmp[" << name << ".Orignal" << names[i] << "] } }\n";
		}
		file << "#endif \n"<< std::endl;
	}

	file << "\n";

	//加载函数
	file << "CRITICAL_SECTION g_cs;"<< std::endl;
	file << "extern \"C\" void LoadProc()"<< std::endl;
	file << "{"<< std::endl;	
	file << "\t\tchar path[MAX_PATH];" << std::endl;
	file << "\t\tEnterCriticalSection(&g_cs);" << std::endl;
	file << "\t\tStringCchCat(path + GetSystemDirectory(path, MAX_PATH - " << fileNameLength << "), MAX_PATH, \"\\\\" << name << ".dll\"" <<  ");" << std::endl;
	file << "\t\tif (ucrtbase.dll) {;" << std::endl;
	file << "\t\t\tLeaveCriticalSection(&g_cs);" << std::endl;
	file << "\t\t\treturn;" << std::endl;
	file << "\t\t}" << std::endl;
	file << "\t\t" << name << ".dll = LoadLibraryEx(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);" << std::endl;
	file << "\t\tif (" << name << ".dll == false)" << std::endl;
	file << "\t\t{" << std::endl;
	file << "\t\t\ttypedef int (WINAPI *XXX)(HWND , LPCWSTR ,  LPCWSTR, UINT);" << std::endl;
	file << "\t\t\t((XXX)GetProcAddress(LoadLibraryW(L\"user32.dll\"), \"MessageBoxW\"))(NULL, L\"Cannot load original ucrtbase.dll library\", L\"\", MB_OK);" << std::endl;
	file << "\t\t\tExitProcess(0);" << std::endl;
	file << "\t\t}" << std::endl;
	file << "\t\telse{" << std::endl;
	for (int i = 0; i < names.size(); i++)
	{
		file << "\t\t\t" << name << ".Orignal" << names[i] << " = GetProcAddress(" << name << ".dll, \"" << names[i] << "\");" << std::endl;
	}
	file << "}"<< std::endl;
	file << "\t\tLeaveCriticalSection(&g_cs);" << std::endl;
	file << "}"<< std::endl;

	//dllmam
	file << "\n";
	file << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {" << endl;
	file << "\tswitch (ul_reason_for_call)" << std::endl;
	file << "\t{" << std::endl;

	file << "\tcase DLL_PROCESS_ATTACH:" << std::endl;
	file << "\t{" << std::endl;
	file << "\t\tDisableThreadLibraryCalls(hModule);" << std::endl;
	file << "\t\tmemset(&ucrtbase, 0, sizeof(ucrtbase));;" << std::endl;
	file << "\t\tInitializeCriticalSection(&g_cs);" << std::endl;
	file << "\t\tbreak;" << std::endl;
	file << "\t}" << std::endl;
	file << "\tcase DLL_PROCESS_DETACH:" << std::endl;
	file << "\t{" << std::endl;
	file << "\t\tFreeLibrary(" << name << ".dll);" << std::endl;
	file << "\t}" << std::endl;
	file << "\tbreak;" << std::endl;
	file << "\t}" << std::endl;
	file << "\treturn TRUE;" << std::endl;
	file << "}" << std::endl;

	file.close();
}

void generateASM(string name, vector<string> names)
{
	std::fstream file;
	file.open(name + "_.asm", std::ios::out);
	std::string strName = "g_p" + name;

	file << ".data" << endl;
	file << "extern " << strName << " : QWORD" << endl;
	file << ".code" << endl;
	file << "EXTERN LoadProc:PROC" << endl;

	
	for (int i = 0; i < names.size(); i++)
	{
		file << "PUBLIC  " << "Fake" << names[i] << i << endl;

	}
	file << "\n" << endl;
	file << "\n" << endl;
	

	for (int i = 0; i < names.size(); i++)
	{
		file << "\t\t\t" << "Fake" << names[i] << i << " proc" << endl;
		file << "\t\t\tpush rax"<< endl;
		file << "\t\t\tcall LoadProc"<< endl;
		file << "\t\t\tpop rax"<< endl;
		file << "\t\t\tmov rax, " << strName << endl;
		int nPos =  8 + 8 * i; 
		file << "\t\t\t" << "jmp qword ptr [ rax "<< " + " << nPos << "]" << endl;
		file << "\t\t\t"<< "Fake" << names[i] << i << " endp" << endl;
		file << "\n" << endl;
	}
	file << "end" << endl;

	file.close();
}

int main(int argc, char *argv[])
{
	std::vector<std::string> args(argv, argv + argc);

	IMAGE_NT_HEADERS headers;
	if (getImageFileHeaders(args[1], headers))
	{
		fileType = headers.FileHeader.Machine;
	}

	// Get filename
	vector<std::string> fileNameV = explode(args[1], '\\');
	std::string fileName = fileNameV[fileNameV.size() - 1];
	fileName = fileName.substr(0, fileName.size() - 4);

	// Get dll export names
	listDLLFunctions(args[1], names);

	// Create Def File
	generateDEF(fileName, names);
	generateMainCPP(fileName, names);
		
	generateASM(fileName, names);

	return 0;
}
