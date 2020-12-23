#include "includes.h"
#include "mem.h"

//event handles for synchronization
HANDLE event_handle = NULL;
HANDLE event_handle2 = NULL;
//Read/Write Buffer struct
RWbuf buffer;


template<typename ... A>
void call_hook_test(const A ... arguments)
{
    void* control_function = GetProcAddress(LoadLibrary("win32u.dll"), "NtQueryCompositionSurfaceStatistics");

    if (!control_function) {
        std::cout << "cannot find hooked func addr";
        return;
    }
    printf("%p address of NtQueryXXX in usermode dll\n", control_function);
    auto func = static_cast<uint64_t(_stdcall*)(A...)>(control_function);
    //std::cout << func << "\n";

    //call the um func which calls the hooked kernel func
    func(arguments ...);

}



DWORD WINAPI km_thread(LPVOID lpParameter) {

    DWORD64 adr = (DWORD64)&buffer;
    //call hook in kernel with address of buffer in um control process as input parameter
    call_hook_test(&adr);
    return 0;

}

int main() {
    //a loadlibrary is required so that calling NtQueryXXX directly doesnt result in a BSOD
    LoadLibrary("user32.dll");

    

    DWORD64 target_proc_base;
    //um target proc name, e.g. notepad.exe
    BYTE target_proc_name[64] = { 0 };

    target_proc_name[0] = L'n';
    target_proc_name[2] = L'o';
    target_proc_name[4] = L't';
    target_proc_name[6] = L'e';
    target_proc_name[8] = L'p';
    target_proc_name[10] = L'a';
    target_proc_name[12] = L'd';
    target_proc_name[14] = L'.';
    target_proc_name[16] = L'e';
    target_proc_name[18] = L'x';
    target_proc_name[20] = L'e';


    

    


    std::cout << "launching KM hook...\n";
    //then launch kernel thread
    
    HANDLE hThreadKM = CreateThread(
        NULL,    // Thread attributes
        0,       // Stack size (0 = use default)
        km_thread, // Thread start address
        NULL,    // Parameter to pass to the thread
        0,       // Creation flags
        NULL);   // Thread id
    if (hThreadKM == NULL)
    {
        // Thread creation failed.
        printf("%s", "KM thread creation failed\n");
        // More details can be retrieved by calling GetLastError()
        return 1;
    }
    std::cout << "KM hook launched and unhooked (probably, check DbgView if you wanna be sure)\n";
    //at this point KM thread is stuck in kernel mode until given COMMAND_QUIT, um process cannot exit until this thread returns!
    Sleep(2000);

    //register event handles (must do this AFTER KM thread launch, or else event havent been created lol)
    event_handle = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Global\\Evnt1");
    if (event_handle == NULL) {
        printf("event1 handle open error: %u\n", GetLastError());
    }
    event_handle2 = OpenEventW(EVENT_ALL_ACCESS, FALSE, L"Global\\Evnt2");
    if (event_handle2 == NULL) {
        printf("event2 handle open error: %u\n", GetLastError());
    }



    printf("target proc name buffer addr: %llx\n", &target_proc_name);
    printf("rwbuffer addr: %llx\n", &buffer);

    //example usage
    //getting base address of target usermode process with its name
    printf("grabbing target usermode process (notepad.exe as example) base address\n");
    issue_comm(COMMAND_GET_UM_PROC_BASE, (DWORD64)&target_proc_base, &target_proc_name, sizeof(target_proc_name));
    printf("target proc base is %llx\n", target_proc_base);
    
    
    
    
    
    //read a float from target usermode process at address baseaddress+0xBEEF
    /*
    float dummyflt;
    issue_comm(COMMAND_RPM, target_proc_base + 0xBEEF , &dummyflt, sizeof(float));
    printf("Float read = %f", dummyfloat);
    
    */

    //write an integer from usermode control process (this process) to target usermode address baseaddress+0xBEEF
    /*
    int dummyint;
    issue_comm(COMMAND_WPM, target_proc_base + 0xBEEF , &dummyint, sizeof(int));

    */
    //exit km thread and then exit um control process
    printf("issuing quit command in 3 seconds...\n");
    Sleep(3000);
    issue_comm(COMMAND_QUIT, NULL, (void*)NULL, sizeof(int));

    printf("END\n");

    
    
}