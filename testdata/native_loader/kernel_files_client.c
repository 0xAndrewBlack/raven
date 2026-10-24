#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static int same(const WCHAR *left,const WCHAR *right)
{
	while(*left && *left==*right) {++left;++right;}
	return *left==*right;
}

static unsigned length(const WCHAR *text)
{
	unsigned count=0;
	while(text[count]) ++count;
	return count;
}

static void join(WCHAR *target,const WCHAR *directory,const WCHAR *name)
{
	unsigned at=0;
	for(unsigned i=0;directory[i];++i) target[at++]=directory[i];
	for(unsigned i=0;name[i];++i) target[at++]=name[i];
	target[at]=0;
}

static int bytes_equal(const char *left,const char *right,unsigned count)
{
	for(unsigned i=0;i<count;++i) if(left[i]!=right[i]) return 0;
	return 1;
}

#define CHECK(code,condition) do { if(!(condition)) return code; } while(0)

int raven_entry(void)
{
	WCHAR temp[260],work[260],path[260],copy[260],moved[260],upper[260],pattern[260];
	CHECK(1,GetTempPathW(260,temp)>3);
	join(work,temp,L"raven-file-test\\");
	WCHAR work_no_slash[260];
	join(work_no_slash,temp,L"raven-file-test");
	// Leftovers from an interrupted earlier run would hide real failures.
	WCHAR cleanup[260];
	join(cleanup,work,L"hello.txt"); DeleteFileW(cleanup);
	join(cleanup,work,L"moved.txt"); DeleteFileW(cleanup);
	join(cleanup,work,L"copy.txt"); DeleteFileW(cleanup);
	join(cleanup,work,L"persist.txt"); DeleteFileW(cleanup);
	RemoveDirectoryW(work_no_slash);
	CHECK(2,CreateDirectoryW(work_no_slash,0));
	CHECK(3,!CreateDirectoryW(work_no_slash,0) && GetLastError()==ERROR_ALREADY_EXISTS);
	CHECK(4,(GetFileAttributesW(work_no_slash)&FILE_ATTRIBUTE_DIRECTORY)!=0);

	join(path,work,L"hello.txt");
	HANDLE file=CreateFileW(path,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
	CHECK(5,file!=INVALID_HANDLE_VALUE);
	DWORD done=0;
	CHECK(6,WriteFile(file,"hello world",11,&done,0) && done==11);
	LARGE_INTEGER size;
	CHECK(7,GetFileSizeEx(file,&size) && size.QuadPart==11);
	CHECK(8,CloseHandle(file));
	file=CreateFileW(path,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
	CHECK(9,file==INVALID_HANDLE_VALUE && GetLastError()==ERROR_FILE_EXISTS);

	file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	CHECK(10,file!=INVALID_HANDLE_VALUE);
	char buffer[32];
	CHECK(11,ReadFile(file,buffer,32,&done,0) && done==11 && bytes_equal(buffer,"hello world",11));
	CHECK(12,ReadFile(file,buffer,32,&done,0) && done==0);
	LARGE_INTEGER offset;
	offset.QuadPart=-5;
	LARGE_INTEGER position;
	CHECK(13,SetFilePointerEx(file,offset,&position,FILE_END) && position.QuadPart==6);
	CHECK(14,ReadFile(file,buffer,5,&done,0) && done==5 && bytes_equal(buffer,"world",5));
	CHECK(15,!WriteFile(file,"x",1,&done,0) && GetLastError()==ERROR_ACCESS_DENIED);
	CloseHandle(file);

	// Windows file names ignore case; the host file system does not.
	join(upper,work,L"HELLO.TXT");
	file=CreateFileW(upper,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	CHECK(16,file!=INVALID_HANDLE_VALUE);
	CloseHandle(file);
	CHECK(17,(GetFileAttributesW(path)&FILE_ATTRIBUTE_DIRECTORY)==0);

	join(copy,work,L"copy.txt");
	const FILETIME written={0x89abcdef,0x01d00000};
	file=CreateFileW(path,GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	CHECK(37,file!=INVALID_HANDLE_VALUE && SetFileTime(file,0,0,&written) && CloseHandle(file));
	CHECK(18,CopyFileW(path,copy,TRUE));
	WIN32_FILE_ATTRIBUTE_DATA copied;
	CHECK(38,GetFileAttributesExW(copy,GetFileExInfoStandard,&copied));
	CHECK(39,copied.ftLastWriteTime.dwLowDateTime==written.dwLowDateTime &&
		copied.ftLastWriteTime.dwHighDateTime==written.dwHighDateTime);
	CHECK(19,!CopyFileW(path,copy,TRUE) && GetLastError()==ERROR_FILE_EXISTS);
	const FILETIME changed={0x12345678,0x01d10000};
	file=CreateFileW(copy,GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	CHECK(40,file!=INVALID_HANDLE_VALUE && SetFileTime(file,0,0,&changed) && CloseHandle(file));
	CHECK(41,CopyFileExW(path,copy,0,0,0,0));
	CHECK(42,GetFileAttributesExW(copy,GetFileExInfoStandard,&copied) &&
		copied.ftLastWriteTime.dwLowDateTime==written.dwLowDateTime &&
		copied.ftLastWriteTime.dwHighDateTime==written.dwHighDateTime);
	join(moved,work,L"moved.txt");
	CHECK(20,MoveFileExW(copy,moved,0));
	CHECK(21,GetFileAttributesW(copy)==INVALID_FILE_ATTRIBUTES && GetLastError()==ERROR_FILE_NOT_FOUND);
	CHECK(22,!MoveFileExW(path,moved,0) && GetLastError()==ERROR_ALREADY_EXISTS);

	join(pattern,work,L"*.txt");
	WIN32_FIND_DATAW data;
	HANDLE find=FindFirstFileW(pattern,&data);
	CHECK(23,find!=INVALID_HANDLE_VALUE && same(data.cFileName,L"hello.txt") && data.nFileSizeLow==11);
	CHECK(24,FindNextFileW(find,&data) && same(data.cFileName,L"moved.txt"));
	CHECK(25,!FindNextFileW(find,&data) && GetLastError()==ERROR_NO_MORE_FILES);
	CHECK(26,FindClose(find));
	join(pattern,work,L"nothing*");
	find=FindFirstFileW(pattern,&data);
	CHECK(27,find==INVALID_HANDLE_VALUE && GetLastError()==ERROR_FILE_NOT_FOUND);

	WCHAR full[260],*part=0;
	CHECK(28,GetFullPathNameW(L"C:\\a\\b\\..\\c.txt",260,full,&part)==10 && same(full,L"C:\\a\\c.txt") && part==full+5);
	CHECK(29,SetCurrentDirectoryW(work_no_slash));
	WCHAR current[260];
	CHECK(30,GetCurrentDirectoryW(260,current)==length(work_no_slash) && same(current,work_no_slash));
	join(full,work,L"relative.txt");
	file=CreateFileW(L"relative.txt",GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
	CHECK(31,file!=INVALID_HANDLE_VALUE);
	CloseHandle(file);
	CHECK(32,GetFileAttributesW(full)!=INVALID_FILE_ATTRIBUTES);
	DeleteFileW(full);

	// The last file stays behind so the test driver can check the host file system independently.
	WCHAR kept[260];
	join(kept,work,L"persist.txt");
	file=CreateFileW(kept,GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
	CHECK(33,file!=INVALID_HANDLE_VALUE && WriteFile(file,"persisted by raven\n",19,&done,0) && done==19);
	CloseHandle(file);

	CHECK(34,DeleteFileW(path) && DeleteFileW(moved));
	CHECK(35,!DeleteFileW(path) && GetLastError()==ERROR_FILE_NOT_FOUND);
	CHECK(36,!RemoveDirectoryW(work_no_slash));
	return 0;
}
