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
    fprintf(stderr, "connect called.\n");
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
        fprintf(stderr, "Unimplemented ptrace surrogate %d.\n", request);
    fprintf(stderr, "ptrace() call denied.\n");
    return 0;
}
void* my_dlsym(void* handle, const char* symbol) {
    fprintf(stderr, "dlsym called: %p %s\n", handle, symbol);
    if (!strcmp(symbol, "ptrace")) 
        return (void*) my_ptrace;
    else
        return dlsym(handle, symbol);
}

bool hideJailbreakingFile(const char* path) {
   const char* lists[] = {
	"/Library/MobileSubstrate/",
	"/Applications/Cydia.app",
	"/var/cache/apt",
	"/var/lib/apt",
	"/var/lib/cydia",
	"/etc/apt",
	NULL
   };
   for(int i=0; lists[i]; i++) {
       if (!strncmp(path, lists[i], strlen(lists[i])))
	       return true;
   }
   return false;
}
int my_stat(const char * path, struct stat * buf) {
    if (hideJailbreakingFile(path)) {
		fprintf(stderr, "stat: hiding %s\n", path);
		return -1;
	} else {
		fprintf(stderr, "stat called: %s\n", path);
		return stat(path, buf);
	}
}

int my_lstat(const char * path, struct stat * buf) {
    if (hideJailbreakingFile(path)) {
		fprintf(stderr, "lstat: hiding %s\n", path);
		return -1;
	} else if (!strcmp(path, "/Applications")) {
		fprintf(stderr, "Hide /Applications symlink.\n");
		int r = lstat(path, buf);
		if (!r) 
			buf->st_mode = (buf->st_mode & (~S_IFMT)) | S_IFDIR;
		return r;
	} else {
		fprintf(stderr, "lstat called: %s\n", path);
		return lstat(path, buf);
	}
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
            fprintf(stderr, "hook_libfunc %s failed.\n", hooks[i].name);
        else
            fprintf(stderr, "hook_libfunc %s succeed: %p.\n", hooks[i].name, ret);
        }
}