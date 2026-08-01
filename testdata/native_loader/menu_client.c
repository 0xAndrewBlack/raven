#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <limits.h>

int raven_entry(void)
{
	HMODULE module=LoadLibraryW(L"menus.dll");
	if (!module) return 1;
	HMENU menu=LoadMenuW(module,MAKEINTRESOURCEW(500)),second=LoadMenuW(module,MAKEINTRESOURCEW(500));
	HMENU extended=LoadMenuW(module,L"named");
	if (!menu || !second || !extended || menu==second) return 2;
	HMENU game=GetSubMenu(menu,0),levels=GetSubMenu(game,2),wide=GetSubMenu(extended,0);
	if (!IsMenu(game) || !IsMenu(levels) || !IsMenu(wide) || GetMenuItemCount(menu)!=2 ||
		GetMenuItemCount(game)!=3 || GetMenuItemCount(levels)!=2 || GetMenuItemCount(extended)!=2) return 3;
	if (GetMenuItemID(menu,0)!=UINT_MAX || GetMenuItemID(menu,1)!=512 || GetMenuItemID(game,0)!=510 ||
		GetMenuItemID(game,1)!=0 || GetMenuItemID(levels,0)!=521 || GetMenuItemID(levels,1)!=523 ||
		GetMenuItemID(wide,0)!=0x12345678 || GetSubMenu(menu,1)) return 4;
	if (GetSubMenu(menu,-1) || GetSubMenu(menu,2) || GetMenuItemID(menu,-1)!=UINT_MAX || GetMenuItemID(menu,2)!=UINT_MAX) return 5;
	{
		/* Replacing the text of an item that sits at the right edge of the menu bar keeps it there. */
		HMENU bar=CreateMenu();
		MENUITEMINFOW info={sizeof info};
		if (!bar || !AppendMenuW(bar,MF_STRING,900,L"left") || !AppendMenuW(bar,MF_STRING|MF_HELP,901,L"right")) return 12;
		if (!ModifyMenuW(bar,901,MF_BYCOMMAND|MF_STRING,901,L"right again")) return 13;
		info.fMask=MIIM_FTYPE;
		if (!GetMenuItemInfoW(bar,1,TRUE,&info) || !(info.fType&MFT_RIGHTJUSTIFY)) return 14;
		if (!GetMenuItemInfoW(bar,0,TRUE,&info) || (info.fType&MFT_RIGHTJUSTIFY)) return 15;
		if (!DestroyMenu(bar)) return 16;
	}
#ifdef MENU_BOUNDARY
	SetLastError(71);
	if (DestroyMenu(levels) || GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED || !IsMenu(levels) || GetMenuItemCount(game)!=3) return 11;
#endif
	if (!FreeLibrary(module) || !IsMenu(menu) || !IsMenu(game) || GetMenuItemCount(levels)!=2 || GetMenuItemID(wide,0)!=0x12345678) return 6;
	if (!DestroyMenu(menu) || IsMenu(menu) || IsMenu(game) || IsMenu(levels) || !IsMenu(second) || !IsMenu(extended)) return 7;
	SetLastError(71);
	if (DestroyMenu(menu) || GetLastError()!=71) return 8;
	SetLastError(71);
	if (GetMenuItemCount(menu)!=-1 || GetLastError()!=71) return 9;
	if (!DestroyMenu(second) || !DestroyMenu(extended) || IsMenu(wide)) return 10;
	return 0;
}
