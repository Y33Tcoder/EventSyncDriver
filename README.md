===EventSyncDriver===

A Windows kernel driver meant to be manually mapped into kernel memory to allow arbitrary read/write access to any usermode process,
via hooking a kernel routine in ntoskrnl.exe and trapping a usermode thread inside a syscall, and unhooking immediately.

This is mainly meant for bypassing kernel anti-cheats which scan for rogue system threads (the ones launched from an address not in a valid base image in memory),
since the usermode thread trapped is technically launched from ntoskrnl, which is backed by a valid image.

Note that this driver is meant to be launched with a manual mapper (e.g. kdmapper), but can be modified into a regular driver to be used for bypasses if you have a valid cert for signing Windows drivers.
kdmapper sources:
- https://github.com/TheCruZ/kdmapper-1803-20H2
- https://github.com/z175/kdmapper

This project must be used in conjunction with a usermode control process (umctrlproc in this repo) which calls a custom API, to issue commands to the driver to do any r/w operations on a target usermode process,
example usage of the usermode control API is given in the umctrlproc main.cpp file.


Please compile both projects (EventSyncDrv and umctrlproc => EventSyncDrv.sys and umctrlproc.exe respectively) as x64 Release. 

Steps to launch this PoC:
1. launch cmd as admin
2. place kdmapper executable, EventSyncDrv.sys and umctrlproc.exe in the current working directory
3. run "kdmapper.exe EventSyncDrv.sys"
4. run "umctrlproc.exe"
5. run the process meant to be targeted by the usermode control process
6. for the example code provided, console should output base address of targeted um process, and then exit after 3 seconds.

ATTENTION: This PoC by itself is not capable of bypassing most kernel anticheats without further modification yourself and cleaning traces leftover by manual driver mapping!

