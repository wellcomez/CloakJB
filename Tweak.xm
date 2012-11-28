/* How to Hook with Logos
Hooks are written with syntax similar to that of an Objective-C @implementation.
You don't need to #include <substrate.h>, it will be done automatically, as will
the generation of a class list and an automatic constructor.

%hook ClassName

// Hooking a class method
+ (id)sharedInstance {
	return %orig;
}

// Hooking an instance method with an argument.
- (void)messageName:(int)argument {
	%log; // Write a message about this call, including its class, name and arguments, to the system log.

	%orig; // Call through to the original function with its original arguments.
	%orig(nil); // Call through to the original function with a custom argument.

	// If you use %orig(), you MUST supply all arguments (except for self and _cmd, the automatically generated ones.)
}

// Hooking an instance method with no arguments.
- (id)noArguments {
	%log;
	id awesome = %orig;
	[awesome doSomethingElse];

	return awesome;
}

// Always make sure you clean up after yourself; Not doing so could have grave consequences!
%end
*/
#include <dlfcn.h>
#include "mach_hook/mach_hook.h"
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
int my_connect(int socket, const struct sockaddr *address, socklen_t address_len) {
    fprintf(stderr, "connect called.");
    if (address) {
        struct sockaddr_in * addr = (struct sockaddr_in*)address;
        if (ntohs(addr->sin_port) == 22 || ntohs(addr->sin_port) == 51022) {
            NSLog(@"Block probing to local SSH port.");
            return ETIMEDOUT;
        }
    }
    return connect(socket, address, address_len);
}

long my_ptrace(int request, pid_t pid, void *addr, void *data) {
    if (request != 31) // ptrace_deny_attach
        fprintf(stderr, "Unimplemented ptrace surrogate %d.", request);
    
    return 0;
}
void* my_dlsym(void* handle, const char* symbol) {
    fprintf(stderr, "dlsym called: %p %s", handle, symbol);
    if (!strcmp(symbol, "ptrace")) 
        return (void*) my_ptrace;
    else
        return dlsym(handle, symbol);
}

int my_stat(const char * path, struct stat * buf) {
    fprintf(stderr, "stat called: %s", path);
    return stat(path, buf);
}

int my_lstat(const char * path, struct stat * buf) {
    fprintf(stderr, "lstat called: %s \n", path);
    return lstat(path, buf);
}

void* hook_libfunc(const char* funcname, void* replacefunc) {
    void *handle = 0;  //handle to store hook-related info
    mach_substitution original = NULL;  //original data for restoration

    // Find an address in main executable
    void* main_symbol = dlsym(RTLD_MAIN_ONLY, "start");
    if (!main_symbol) {
        fprintf(stderr, "Cannot find start() in the main executable.\n");
        //return NULL;
        main_symbol = (void*)0x1000;
    }
    
	Dl_info info;
	if (!dladdr(main_symbol, &info))  // Get main executable information
    {
        fprintf(stderr, "Failed to get the base address of the main executable!\n");
        return NULL;
    }

    handle = mach_hook_init(info.dli_fname, info.dli_fbase);
    if (!handle)
    {
        fprintf(stderr, "mac_hook_init on %p %s failed!\n", info.dli_fbase, info.dli_fname);
        return NULL;
    }

    original = mach_hook(handle, funcname, (mach_substitution)replacefunc);

    if (!original)
    {
        fprintf(stderr, "mach_hook %s failed!\n", funcname);
        goto end;
    }
end:
    mach_hook_free(handle);
    return (void*)original;
}

struct Hook{
    const char* name;
    void* func;
};
struct Hook hooks[] = {
    {"dlsym", (void*)my_dlsym},
    {"stat",  (void*)my_stat},
    {"lstat",  (void*)my_lstat},
    {"connect", (void*)my_connect},
    {NULL, NULL}
};

__attribute__((constructor))
static void initializer() {
    NSLog(@"CloakJB dylib loaded.");
    for(int i=0; hooks[i].name; i++) {
        void* ret = hook_libfunc(hooks[i].name, hooks[i].func);
        if(!ret)
            NSLog(@"hook_libfunc %s failed.", hooks[i].name);
        else
            NSLog(@"hook_libfunc %s succeed: %p.", hooks[i].name, ret);
        }
}