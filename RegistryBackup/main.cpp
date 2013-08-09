#include <windows.h>                            
#include <string>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include "comutil.h"
#include <ctime>
#include "LogCommon/ScopedPrivilege.hpp"        //no errors on this line
#include "LogCommon/Win32Exception.hpp"            //no errors on this line
#include "LogCommon/Library.hpp"            //no errors on this line

using namespace std;
using Instalog::SystemFacades::ScopedPrivilege;  //no errors on this line
using Instalog::SystemFacades::Win32Exception;   //no errors on this line

#pragma comment(lib, "LogCommon.lib")
//#pragma comment(lib, "cmcfg32.lib")

BOOL SetPrivilege (
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    )
{
    TOKEN_PRIVILEGES tp;
    DWORD cb=sizeof(TOKEN_PRIVILEGES);
    LUID luid;

    if ( !LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup
            &luid ) )        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() );
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

   if ( !AdjustTokenPrivileges(
           hToken,
           FALSE,
           &tp,
           cb,
           NULL,
           NULL) )
    {
          printf("AdjustTokenPrivileges error: %u\n", GetLastError() );
          return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("The token does not have the specified privilege. \n");
          return FALSE;
          /*
            The token does not have one or more of the privileges specified in the NewState parameter.
            The function may succeed with this error value even if no privileges were adjusted.
            The PreviousState parameter indicates the privileges that were adjusted.
          */
    }
    return TRUE;
}

BOOL IsAppRunningAsAdminMode()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    // Allocate and initialize a SID of the administrators group.
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    // Determine whether the SID of administrators group is enabled in
    // the primary access token of the process.
    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:
    // Centralized cleanup for all allocated resources.
    if (pAdministratorsGroup)
    {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    // Throw the error if something failed in the function.
    if (ERROR_SUCCESS != dwError)
    {
        throw dwError;
    }

    return fIsRunAsAdmin;
}
 

int main() {
    
    bool fIsRunAsAdmin = IsAppRunningAsAdminMode();
    if (fIsRunAsAdmin == false)
    {
            wchar_t szPath[MAX_PATH];
            if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)))
            {
                // Launch itself as admin
                SHELLEXECUTEINFO sei = { sizeof(sei) };
                sei.lpVerb = L"runas";
                sei.lpFile = szPath;
                sei.hwnd = NULL;
                sei.nShow = SW_NORMAL;
                if (!ShellExecuteEx(&sei))
                {
                    DWORD dwError = GetLastError();
                    if (dwError == ERROR_CANCELLED)
                    {
                        // The user refused to allow privileges elevation.
                        std::cout << "User did not allow elevation" << std::endl;
                    }
                }
                else
                {
                    return 0;
                }
            }
    }
    else {
        //do nothing since process already elevated
    }

    //const wchar_t* file1 = L"c:\\abcdefgRegBackup\\backup_yyyymmddhhmmss\\HKCR"; //no errors on this line
    const wchar_t* Save_location1 = L"c:\\InstalogRegBackup\\";
    
            HANDLE hToken;
    
            if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            {
                return FALSE;
            }
    
            {
            //OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
            SetPrivilege(hToken,L"SeBackupPrivilege",1 );
    

            //ScopedPrivilege guard(SE_BACKUP_NAME); //no errors on this line

            BOOL resultA = ::CreateDirectory(Save_location1, NULL);
            //std::wcout << "Value of resultA is: " << resultA << endl; // "1" is output to screen!
            //Sleep(3000);
    
            //std::wcout << "Value of GetLastError() is: " << GetLastError() << endl; // "1300" is output to screen!
            //Sleep(3000);

            //std::wstring example(L"abc");
            //std::wcout << "Value of example is: "<< example.c_str();

            //float f = time(0);
            //std::string f_str = std::to_string(f);
            //std::wcout << "Value of f_str is: " << f_str << '\n';

            const time_t t = time(0);   // get time now
            struct tm * now = localtime(&t);
            //   wcout //<< "localtime(t) " << localtime(&t) << endl
            //     << "Year " << (now->tm_year + 1900) << '-'
            //        << "Month " << (now->tm_mon + 1) << '-'
            //        << "Day " << now->tm_mday << endl
            //     << "Hour " << now->tm_hour << endl
            //     << "Minute " << (now->tm_min + 1) << endl;
            //Sleep(3000);

            wstring resultB2 = L"_";
            wstring resultB3 = to_wstring((now->tm_year + 1900));
            wstring resultB4 = to_wstring((now->tm_mon + 1)) ;
            wstring resultB5 = to_wstring(now->tm_mday) ;
            wstring resultB6 = to_wstring(now->tm_hour) ;
            wstring resultB7 = to_wstring((now->tm_min + 1));

            resultB2 += resultB3;
            resultB2 += resultB4;
            resultB2 += resultB5;
            resultB2 += resultB6;
            resultB2 += resultB7;

            //wcout << "ResultB2 is now: " << resultB2 << endl; //_20126141314
            //Sleep(3000);

            //std::wstring resultB8 = std::wstring(resultB2.begin(), resultB2.end());
            //wcout << "ResultB8 is: " << resultB8 << endl;
            //Sleep(3000);

            //const wchar_t* widecstr = resultB8.c_str();
            //wcout << "widecstr is now: " << widecstr << endl; // 003FE8F0 -- huh? why?
            //Sleep(3000);

            //wstring wstr = resultB2;

            wstring ws1 = L"c:\\InstalogRegBackup\\backup", ws2 = resultB2; //_20126141314
            std::wstring s(ws1);
            s += std::wstring(ws2);

            //std::wcout << "s is now: " << s << std::endl;
            Sleep(3000);//

            const wchar_t *save_loc2 = s.c_str();
            wcout << "save_loc2 is now: " << save_loc2 << endl; // c:\InstalogRegBackup\backup_20126141314
            //Sleep(3000);

            //const wchar_t* Save_location2 = L"c:\\InstalogRegBackup\\backup";
            //Save_location2 += s; //hoping to get "c:\\InstalogRegBackup\\backup00X_yyyymmddhhmmss\\_20126141314" not "c:\\InstalogRegBackup\\backup00X_yyyymmddhhmmss\\003FE8F0"

            BOOL resultB = ::CreateDirectory(save_loc2, NULL);
            //std::wcout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            //Sleep(3000);
            std::wcout << "Value of resultB is: " << resultB << endl; // "1" is output to screen.
            Sleep(3000);
    
            //=============================================
            //hklm_hardware.bak
            wstring ws3 = save_loc2, ws4 = L"\\hklm_hardware.bak"; //save_loc2 = c:\InstalogRegBackup\backup_20126141314
            std::wstring s1(ws3);
            s1 += std::wstring(ws4);

            //std::wcout << "s1 is now: " << s1 << std::endl; //s1 = c:\InstalogRegBackup\backup_20126141314\hklm.bak
            //Sleep(3000);

            const wchar_t *save_loc3 = s1.c_str();
            wcout << "save_loc3 is now: " << save_loc3 << endl; // save_loc3 = c:\InstalogRegBackup\backup_20126141314\hklm_hardware
            Sleep(3000);
    
            HKEY hKey;
    
            long resultC1 = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE", 0, KEY_READ, &hKey);
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC1 is: " << resultC1 << endl; // "0" is output to screen.
            Sleep(3000);
    
            long resultC2 = ::RegSaveKeyW(hKey, save_loc3, NULL); //no errors on this line
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC2 is: " << resultC2 << endl; // "0" is output to screen!
            Sleep(3000);

            //=============================================
            //hku_default.bak
            wstring ws5 = save_loc2, ws6 = L"\\hku_default.bak"; //save_loc2 = c:\InstalogRegBackup\backup_20126141314
            std::wstring s2(ws5);
            s2 += std::wstring(ws6);

            //std::wcout << "s2 is now: " << s2 << std::endl; //s2 = c:\InstalogRegBackup\backup_20126141314\hkcr.bak
            //Sleep(3000);

            const wchar_t *save_loc4 = s2.c_str();
            wcout << "save_loc4 is now: " << save_loc4 << endl; // save_loc4 = c:\InstalogRegBackup\backup_20126141314\hkcr.bak
            Sleep(3000);
    
            HKEY hKey2;

            long resultC3 = ::RegOpenKeyExW(HKEY_USERS, L".default", 0, KEY_READ, &hKey2);
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC3 is: " << resultC3 << endl; // "0" is output to screen.
            Sleep(3000);

            long resultC4 = ::RegSaveKeyW(hKey2, save_loc4, NULL); //no errors on this line
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC4 is: " << resultC4 << endl; // "0" is output to screen!
            Sleep(3000);

            //=============================================
            //hklm_software.bak
            wstring ws7 = save_loc2, ws8 = L"\\hklm_software.bak"; //save_loc2 = c:\InstalogRegBackup\backup_20126141314
            std::wstring s3(ws7);
            s3 += std::wstring(ws8);

            //std::wcout << "s3 is now: " << s3 << std::endl; //s3 = c:\InstalogRegBackup\backup_20126141314\hklm_software.bak
            //Sleep(3000);

            const wchar_t *save_loc5 = s3.c_str();
            wcout << "save_loc5 is now: " << save_loc5 << endl; // save_loc5 = c:\InstalogRegBackup\backup_20126141314\hklm_software
            Sleep(3000);
    
            HKEY hKey3;
    
            long resultC5 = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_READ, &hKey3);
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC5 is: " << resultC5 << endl; // "0" is output to screen.
            Sleep(3000);
    
            long resultC6 = ::RegSaveKeyW(hKey3, save_loc5, NULL); //no errors on this line
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC6 is: " << resultC6 << endl; // "0" is output to screen!
            Sleep(3000);

            //=============================================
            //hklm_system.bak
            wstring ws9 = save_loc2, ws10 = L"\\hklm_system.bak"; //save_loc2 = c:\InstalogRegBackup\backup_20126141314
            std::wstring s4(ws9);
            s4 += std::wstring(ws10);

            //std::wcout << "s4 is now: " << s4 << std::endl; //s4 = c:\InstalogRegBackup\backup_20126141314\hklm_system.bak
            //Sleep(3000);

            const wchar_t *save_loc6 = s4.c_str();
            wcout << "save_loc6 is now: " << save_loc6 << endl; // save_loc5 = c:\InstalogRegBackup\backup_20126141314\hklm_system.bak
            Sleep(3000);
    
            HKEY hKey4;
    
            long resultC7 = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hKey4);
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC7 is: " << resultC7 << endl; // "0" is output to screen.
            Sleep(3000);
    
            long resultC8 = ::RegSaveKeyW(hKey4, save_loc6, NULL); //no errors on this line
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC8 is: " << resultC8 << endl; // "0" is output to screen!
            Sleep(3000);

            //=============================================
            //hklm_security.bak
            wstring ws11 = save_loc2, ws12 = L"\\hklm_security.bak"; //save_loc2 = c:\InstalogRegBackup\backup_20126141314
            std::wstring s5(ws11);
            s5 += std::wstring(ws12);

            //std::wcout << "s4 is now: " << s4 << std::endl; //s4 = c:\InstalogRegBackup\backup_20126141314\hklm_security.bak
            //Sleep(3000);

            const wchar_t *save_loc7 = s5.c_str();
            wcout << "save_loc7 is now: " << save_loc7 << endl; // save_loc5 = c:\InstalogRegBackup\backup_20126141314\hklm_security.bak
            Sleep(3000);
    
            HKEY hKey5;
    
            long resultC9 = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SECURITY", 0, KEY_READ, &hKey5);
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC9 is: " << resultC9 << endl; // "5" is output to screen.
            Sleep(3000);
    
            long resultC10 = ::RegSaveKeyW(hKey5, save_loc7, NULL); //no errors on this line
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC10 is: " << resultC10 << endl; // "6" is output to screen!
            Sleep(3000);

            //=============================================
            //hklm_sam.bak
            wstring ws13 = save_loc2, ws14 = L"\\hklm_sam.bak"; //save_loc2 = c:\InstalogRegBackup\backup_20126141314
            std::wstring s6(ws13);
            s6 += std::wstring(ws14);

            //std::wcout << "s4 is now: " << s4 << std::endl; //s4 = c:\InstalogRegBackup\backup_20126141314\hklm_sam.bak
            //Sleep(3000);

            const wchar_t *save_loc8 = s6.c_str();
            wcout << "save_loc8 is now: " << save_loc8 << endl; // save_loc5 = c:\InstalogRegBackup\backup_20126141314\hklm_sam.bak
            Sleep(3000);
    
            HKEY hKey6;
    
            long resultC11 = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hKey6);
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC11 is: " << resultC11 << endl; // "0" is output to screen.
            Sleep(3000);
    
            long resultC12 = ::RegSaveKeyW(hKey6, save_loc8, NULL); //no errors on this line
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC12 is: " << resultC12 << endl; // "0" is output to screen!
            Sleep(3000);

            //=============================================
            //hklm_components.bak
            wstring ws15 = save_loc2, ws16 = L"\\hklm_components.bak"; //save_loc2 = c:\InstalogRegBackup\backup_20126141314
            std::wstring s7(ws15);
            s7 += std::wstring(ws16);

            //std::wcout << "s4 is now: " << s4 << std::endl; //s4 = c:\InstalogRegBackup\backup_20126141314\hklm_components.bak
            //Sleep(3000);

            const wchar_t *save_loc9 = s7.c_str();
            wcout << "save_loc7 is now: " << save_loc7 << endl; // save_loc5 = c:\InstalogRegBackup\backup_20126141314\hklm_components.bak
            Sleep(3000);
    
            HKEY hKey7;
    
            long resultC13 = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"COMPONENTS", 0, KEY_READ, &hKey7);
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC13 is: " << resultC13 << endl; // "2" is output to screen.
            Sleep(3000);
    
            long resultC14 = ::RegSaveKeyW(hKey7, save_loc9, NULL); //no errors on this line
            std::cout << "Value of GetLastError() is: " << GetLastError() << endl; // "0" is output to screen!
            Sleep(3000);
            std::wcout << "Value of resultC14 is: " << resultC14 << endl; // "6" is output to screen!
            Sleep(3000);

            CloseHandle(hToken);
            }
    return 0;
}