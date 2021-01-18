#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <conio.h>
#include <excpt.h>

void sidt() {
	unsigned char	idtr[6];
	unsigned long	idt = 0;

	_asm sidt idtr
	idt = *((unsigned long*)&idtr[2]);

	if ((idt >> 24) == 0xff)
		printf("VM detected\n");
	else
		printf("VM not detected\n");

}

void sldt() {
	unsigned char   ldtr[5] = "\xef\xbe\xad\xde";
	unsigned long   ldt = 0;

	_asm sldt ldtr
	ldt = *((unsigned long*)&ldtr[0]);

	if (ldt == 0xdead0000)
		printf("VM not detected\n");
	else
		printf("VM detected\n");
}

void sgdt() {
	unsigned char   gdtr[6];
	unsigned long   gdt = 0;

	_asm sgdt gdtr
	gdt = *((unsigned long*)&gdtr[2]);

	if ((gdt >> 24) == 0xff)
		printf("VM detected\n");
	else
		printf("VM not detected\n");
}

void str() {
	unsigned char	mem[4] = { 0, 0, 0, 0 };

	__asm str mem;

	if ((mem[0] == 0x00) && (mem[1] == 0x40))
		printf("VM detected\n");
	else
		printf("VM not detected\n");
}

void smsw() {
	unsigned int reax = 0;

	__asm
	{
		mov eax, 0xCCCCCCCC;
		smsw eax;
		mov DWORD PTR[reax], eax;
	}

	if ((((reax >> 24) & 0xFF) == 0xcc) && (((reax >> 16) & 0xFF) == 0xcc))
		printf("VM detected\n");
	else
		printf("VM not detected\n");
}

void vmware_get_memory() {
	unsigned int	a = 0;

	__try {
		__asm {
			push eax
			push ebx
			push ecx
			push edx

			mov eax, 'VMXh'
			mov ecx, 14h
			mov dx, 'VX'
			in eax, dx
			mov a, eax

			pop edx
			pop ecx
			pop ebx
			pop eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	if (a > 0)
		printf("VMWare detected\n");
	else
		printf("VMWare not detected\n");
}

void vmware_get_version() {
	unsigned int	a, b;

	__try {
		__asm {
			push eax
			push ebx
			push ecx
			push edx

			mov eax, 'VMXh'
			mov ecx, 0Ah
			mov dx, 'VX'
			in eax, dx
			mov a, ebx
			mov b, ecx

			pop edx
			pop ecx
			pop ebx
			pop eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	if (a == 'VMXh')
		printf("VM detected\n");
	else
		printf("VM not detected\n");
}

DWORD __forceinline IsInsideVPC_exceptionFilter(_EXCEPTION_POINTERS* ep)
{
	PCONTEXT ctx = ep->ContextRecord;

	ctx->Ebx = -1;
	ctx->Eip += 4; 
	return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL virtualpc_detect()
{
	bool rc = false;

	__try {
		__asm {
			push eax
			push ebx
			push ecx
			push edx

			mov ebx, 0h
			mov eax, 01h

			__emit 0Fh
			__emit 3Fh
			__emit 07h
			__emit 0Bh

			test ebx, ebx
			setz[rc]

			pop edx
			pop ecx
			pop ebx
			pop eax
		}
	}
	__except (IsInsideVPC_exceptionFilter(GetExceptionInformation())) {
		rc = false;
	}
	return rc;
}

int _tmain(int argc, _TCHAR* argv[]) {

	int opt = 0;
	BOOL vpc = false;

	printf("Virtual Machine detection tool \n\n");
	printf("1 - SGDT \n");
	printf("2 - SLDT \n");
	printf("3 - STR \n");
	printf("4 - SMSW \n");
	printf("5 - VMWare get memory\n");
	printf("6 - VMWare get version\n");
	printf("7 - VirtualPC detection\n\n");
	scanf_s("%d", &opt);
	switch (opt) {
	case 1: sgdt();
		break;
	case 2: sldt();
		break;
	case 3: str();
		break;
	case 4: smsw();
		break;
	case 5: vmware_get_memory();
		break;
	case 6: vmware_get_version();
		break;
	case 7: vpc = virtualpc_detect();
		if (vpc)
			printf("VirtualPC detected\n");
		else
			printf("VirtualPC not detected\n");
		break;
	default: printf("Invalid option\n");
		break;
	}

	_getch();
	return 0;
}

