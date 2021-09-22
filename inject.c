#define _GNU_SOURCE
#include </usr/include/x86_64-linux-gnu/sys/mman.h>
#include <dlfcn.h>
#include </usr/include/x86_64-linux-gnu/sys/ptrace.h>
#include </usr/include/x86_64-linux-gnu/sys/types.h>
#include </usr/include/x86_64-linux-gnu/sys/wait.h>
#include <unistd.h>
#include </usr/include/x86_64-linux-gnu/sys/user.h>   
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include </usr/include/x86_64-linux-gnu/sys/reg.h> 
#include <math.h>
#include </usr/include/x86_64-linux-gnu/sys/syscall.h> 
#include </usr/include/x86_64-linux-gnu/sys/stat.h> 
#include </usr/include/x86_64-linux-gnu/sys/types.h> 
#include <fcntl.h>
#include </usr/include/x86_64-linux-gnu/sys/uio.h> 
#include <regex.h>

typedef unsigned long long ull;

static void usage(char *arg){

	printf("Usage %s <pid> <lib-inject-into> <lib-to-inject>", arg);
	
}

/*
 * Check if line respect contains the lib and if so it extracts the adress
 */
static ull parse_mapping(char *line, char *lib) {
	
	ull addr;
	char perms[5];

	if(!strstr(line, lib)){
		return 0;
	}
	
	sscanf(line, "%lx-%*lx %s %*s", &addr, perms);
	if(!strstr(perms, "x")){
		return 0;
	}
	return addr;
}

static ull get_mapping_lib(pid_t pid, char *lib){
	
	FILE *f;
	char path[128]; 
      	char *line = NULL;
	ssize_t read; // signed 
	size_t len; // unsigned 
	sprintf(path, "/proc/%d/maps", pid);
	
	if (!(f=fopen(path, "r"))){
		fprintf(stderr, "Error opening maps file %s", strerror(errno));
		exit(-1);
	}
	
	ull addr=0;	
       	while ((read = getline(&line, &len, f)) != -1) {
		if((addr=parse_mapping(line, lib))){
			break;
		}
    	}
	
    	if (line) {
		free(line);
	}
	fclose(f);
	return addr;
}

// Find offset of a function in library
static ull find_offset(char *lib) {

   
    void* libc_handle = NULL;
    void* __libc_dlopen_mode_addr = NULL;
    char buff[120];
    libc_handle = dlopen(lib, RTLD_NOW);
    __libc_dlopen_mode_addr = dlsym(libc_handle, "__libc_dlopen_mode");
    //printf("__libc_dlopen_mode addr: %p\n", __libc_dlopen_mode_addr);
    dlclose(libc_handle);
    // get the libc address of the current process
    ull addr = get_mapping_lib(getpid(), lib);	
    //return the offset
    return (ull)__libc_dlopen_mode_addr - addr;
	
}

// #############  PTRACE #################

// Writes data of size len at dst of process with PID=pid taken from src
static int ptraceWrite(pid_t pid, unsigned char *src, void *dst, int len) {
	
	ull  *s =  (ull *) src;
	ull *d = (ull *) dst
		;
	// increment by 8 bytes (64 bit words)
	for(int i=0; i<len; i+=sizeof(ull), s++, d++){
		if(ptrace(PTRACE_POKETEXT, pid, d, *s) == -1){
			fprintf(stderr, "Error ptrace POKE %s", strerror(errno));
			return -1;
		}
	}
	return 0;
}
// Read from address addr of process with PID=pid a data of length len and store it in data
static void ptraceRead(int pid, ull addr, void *store, int len) {
	
	if(len % 8){
		fprintf(stderr, "Len to read is not a multiple of 8 - aborting");
		exit(1);
	}
	
	ull *ptr = (ull *)store;
	ull word;

	for (int i=0; i < len; i+=sizeof(ull), ptr++, word=0) {
		if ((word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL)) == -1) {;
			printf("[!] Error reading process memory %s \n ", strerror(errno));
			exit(1);
		}
		*ptr = word; 
	}
}


// Allocate memory of size size in the memory space of process with pid pid. 
// Once allocate the function writes the lib path in the new location  
static int allocate_memory_and_write(pid_t pid, size_t size, char *lib_path, ull __addr__dlopen) {
	
	struct user_regs_struct regs, regs2;
	unsigned char *mmapsysc = "\x0f\x05\x00\x00\x00\x00\x00\x00"; // execute a mmap syscall- opcode OfO5 
	unsigned char *callfunc = "\xff\xd0\xcc\x00\x00\x00\x00\x00"; // call opcode
	unsigned int size_instruction = 8;
	unsigned char restoresegment[8];
	int status;

	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) ==  -1){
		fprintf(stderr, "Error attaching with ptrace %s", strerror(errno));
		return 0;
	}

	printf("Waiting for SIGTRAP\n");
	wait(&status);
	if(WIFEXITED(status)){
		printf("The process has died ;(\n");
		return 0;
	}
	
	if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1){
		fprintf(stderr, "Error attaching with ptrace %s", strerror(errno));
		return 0;
	}
	// saving old registers and data pointed by rip
	memcpy(&regs2, &regs, sizeof(struct user_regs_struct));
	ptraceRead(pid, (unsigned long long)regs.rip, restoresegment, size_instruction);

	// writing the new data for memory allocation
	printf("Injecting code for memory allocation at %p\n", (void*)regs.rip);
	ptraceWrite(pid, mmapsysc, (void*)regs.rip, size_instruction);
	
	// set syscall registers
	regs.rax = 9;  // NR_MMAP;
	regs.rsi = size; // size of the mapping
	regs.rdi = 0;
 	regs.rdx = PROT_WRITE | PROT_READ; // read and writable zone
        regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE; // copy on write on the zone
        regs.r8  = 0;
        regs.r9  = 0;	
	
	if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1){
		fprintf(stderr, "Error setting regs with ptrace %s", strerror(errno));
		return 0;
	}
	
	if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1){
		fprintf(stderr, "Error setting regs with ptrace %s", strerror(errno));
		return 0;
	}
	waitpid(pid, &status, 0);	
	if(WIFEXITED(status)){
		printf("The process has died after singlestep;(\n");
		return 0;
	}
	if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1){
		fprintf(stderr, "Error getting regs with ptrace %s", strerror(errno));
		return 0;
	}
	
	if(regs.rax == 0x0){
		fprintf(stderr, "Error allocating memory\n");
		exit(-1);
	}
	
	ull freeeadr = regs.rax; 
	ptraceWrite(pid, (unsigned char*)lib_path,  (void *)regs.rax, strlen(lib_path)+1);
	memcpy(&regs, &regs2, sizeof(struct user_regs_struct));
	ptraceWrite(pid, callfunc, (void*)regs.rip, size_instruction);
	// write the library at the freed addr and then open it 
	regs.rdi = freeeadr;	
	regs.rax = __addr__dlopen;
	regs.rsi = RTLD_NOW;
	regs.rsp = freeeadr + 4096; // middle of the allocated area (regs.rax + 4096)
	regs.rbp = regs.rsp;
	
	if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1){
		fprintf(stderr, "Error setting regs with ptrace %s", strerror(errno));
		return 0;
	}
	
	if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1){
		fprintf(stderr, "Error continue  with ptrace %s", strerror(errno));
		return 0;
	}
	
	waitpid(pid, &status,0);
	if(WIFEXITED(status)){
		fprintf(stderr, "The process has died after libopen;(\n");
		return 0;
	}
	// Restoring the old instructions	
	ptraceWrite(pid, restoresegment, (void *)regs2.rip, size_instruction);
	if(ptrace(PTRACE_SETREGS, pid, NULL, &regs2) == -1){
		fprintf(stderr, "Error setting regs with ptrace back %s\n", strerror(errno));
		return 0;
	}
		
	if(ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1){
		fprintf(stderr, "Error detaching with ptrace %s", strerror(errno));
		return 0;
	}
	// the new adress is in the rax CPU pointer
	return regs.rax;
}

/*
 * Copy the content of src to file dst
 */
static int copy_file(char *src, char *dst){
	
       FILE *fsrc, *fdst;
       if(!(fsrc=fopen(src, "rb"))) return 0;
       if(!(fdst=fopen(dst, "wb"))) return 0;
      
       unsigned int nbr, nbw;
       char c; 
       nbr = fread(&c, sizeof(char), 1, fsrc);

       while(nbr == 1){
       	 nbw = fwrite(&c, sizeof(char), 1, fdst);
       	 if(nbw < 1){
	 	fclose(fsrc);
		fclose(fdst);
		return 0;
	 } 
	 nbr = fread(&c, sizeof(char), 1, fsrc);
       }
       
       fclose(fsrc);
       fclose(fdst);	  
       return 1;

}

int main(int argc, char* argv[]) {
	if(argc != 4){
		usage(argv[0]);
		exit(-1);
	}
	// take arguments -> @todo error handling
	int pid = atoi(argv[1]);
	char *lib = argv[2];
	char *libtoinject = argv[3];
	
	ull offset = find_offset("/usr/lib/x86_64-linux-gnu/libc-2.31.so");
	ull target_lib_addr = get_mapping_lib(pid, lib);
	ull target_lib_func_addr = target_lib_addr + offset;
	ull allocated_addr;
	
	// The library is going to be copied under /tmp/inject.so -> problems when injecting in root process?
	
	int res = copy_file(libtoinject, "/tmp/inject.so");	
	if(!res){
		fprintf(stderr, "Error copying %s ", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(!(allocated_addr=allocate_memory_and_write(pid, 4096, "/tmp/inject.so\x00", target_lib_func_addr))) {
	       printf("Exiting\n");	     
	       exit(EXIT_FAILURE) ; 	
	}
	return 0;
}
