/*
 *  main.c
 *  ExceptionTest
 *
 *  Created by Charlie Miller on 12/15/06.
 *  Copyright 2006 __MyCompanyName__. All rights reserved.
 *
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <string.h>
#include <mach/thread_status.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include "Exception.h"
#include "implementation.h"
#include "MacDll.h"
#include "dyld.h"

#define EXCEPTION_BREAKPOINT            0x80000003


mach_port_t exception_port;
char *buf;
int pid;
extern mach_port_t the_thread;

void handle_breakpoint(int thread, int addy);

static void print(char *thebuf){
        int i;
        for(i=0; i<16; i++){
                //printf("%02x", thebuf[i] & 0xff);
        }
        //printf("\n");
}

static void printaddy(int addy){
        char *before = malloc(16);
        read_memory(pid, addy, 16, before);
        print(before);
}
/*
static void printprot(int addy){
        unsigned int baseaddr, prot=0, size;
        baseaddr = addy;
        virtual_query(pid, &baseaddr, &prot, &size);
        //printf("Protection: %x\n", prot);
}
*/
static void setbp(int addy){
        printaddy(addy);

        unsigned int baseaddr, prot, size;
        baseaddr = addy;
        virtual_query(pid, &baseaddr, &prot, &size);
        virtual_protect(pid, addy, 1, 0x00000040);
        read_memory(pid, addy, 1, buf);
        baseaddr = addy;
        virtual_query(pid, &baseaddr, &prot, &size);
        virtual_protect(pid, addy, 1, 0x00000020);

        baseaddr = addy;
        virtual_query(pid, &baseaddr, &prot, &size);
        virtual_protect(pid, addy, 1, 0x00000040);
        write_memory(pid, addy, 1, "\xCC");
        baseaddr = addy;
        virtual_query(pid, &baseaddr, &prot, &size);
        virtual_protect(pid, addy, 1, 0x00000020);

        printaddy(addy);
}

void handle_breakpoint(int thread, int addy){        
        i386_thread_state_t state;
        memset(&state, 0x0, sizeof(i386_thread_state_t));
        virtual_protect(pid, addy, 1, 0x00000040);
        write_memory(pid, addy, 1, buf);
        virtual_protect(pid, addy, 1, 0x00000020);
        //printf("Broke at %x\n", addy);
        
        get_context(thread, &state);
		//printf("Got %x %x %x %x %x\n", state.eax, state.ecx, state.edx, state.ebx, state.eip);
        //printf("Context thought we were at %x.  Of course we know we were at %x\n", state.eip, addy+1);
        state.eip--;
		int ret =  set_context(thread, &state);
		if(ret == 1){
				//printf("It said it worked\n");
		} else {
			//	printf("It said it failed\n");
		}
        memset(&state, 0x0, sizeof(i386_thread_state_t));
        get_context(thread, &state);
		//printf("Got %x %x %x %x %x\n", state.eax, state.ecx, state.edx, state.ebx, state.eip);
        //printf("Reset eip to %x", state.eip);
}


int main(int argc, char *argv[]){
        pid = atoi(argv[1]);
        int addy = 0x00001f96;
        buf = malloc(16);
        attach(pid, &exception_port);

//        printprot(addy);

        setbp(addy);

	int id, ec;
	unsigned int  eat, eref;

	while(1){
		if(my_msg_server(exception_port, 100, &id, &ec, &eat, &eref)){

			handle_breakpoint(the_thread, addy);

			resume_thread(the_thread);

			setbp(addy);
			
		}
	}

		return 0;
}


//int main(int argc, char *argv[]){
//	CreateProcessA(NULL, "/Applications/Safari.app/Contents/MacOS/Safari /Users/cmiller/PaiMei-1.1-REV122/console/output/5.mov", 0, 0, 0, 0 , 0 ,0,0,0);
//        pid_t pid = atoi(argv[1]);
//        int addy = 0x00001f96;
//		detach(pid);
//		DebugActiveProcess(pid);
//		unsigned int addr = 0xdeadbeef;
//		int ret = macosx_locate_dyld(pid, &addr);
//		printf("Returned with %d, got addr of 0x%x\n", ret, addr);
//		DebugActiveProcessStop(pid);
//	return 0;
//}