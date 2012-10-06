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

void* my_dlsym(void* handle, const char* symbol) {
    NSLog(@"dlsym called: %x %s", handle, symbol);
    return dlsym(handle, symbol);
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
        fprintf(stderr, "mac_hook_init on %x %s failed!\n", info.dli_fbase, info.dli_fname);
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


__attribute__((constructor))
static void initializer() {
    NSLog(@"CloakJB dylib loaded.");
    if (!hook_libfunc("dlsym", (void*)my_dlsym))
        NSLog(@"hook_libfunc failed.");
}