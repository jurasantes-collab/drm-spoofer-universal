// This is the public API for Zygisk modules.
// DO NOT MODIFY ANY CODE IN THIS FILE.

#pragma once

#include <jni.h>

#define ZYGISK_API_VERSION 4

/*

Define a class and inherit zygisk::ModuleBase to implement the functionality of your module.
Use the macro REGISTER_ZYGISK_MODULE(className) to register that class to Zygisk.

Please note that modules will only be loaded after zygote has forked the child process.
THIS MEANS ALL OF YOUR CODE RUNS IN THE CHILD PROCESS, NOT THE ZYGOTE PROCESS.
Be aware of potential multi-threading issues when creating threads in the child process.

*/

namespace zygisk {

struct Api;
struct AppSpecializeArgs;
struct ServerSpecializeArgs;

class ModuleBase {
public:

    // This method is called as soon as the module is loaded into the target process.
    // A Zygisk JNIEnv pointer will be passed to this function.
    virtual void onLoad([[maybe_unused]] Api *api, [[maybe_unused]] JNIEnv *env) {}

    // This method is called before the app process is specialized.
    // At this point, the process just got forked from zygote, but no app specific specialization
    // is applied. This means that the process does not have any sandbox restrictions and
    // still runs with the same privilege of zygote.
    //
    // All the arguments that will be sent and used for app specialization is passed as a single
    // AppSpecializeArgs object. You can read and overwrite these arguments to change how the app
    // process will be specialized.
    //
    // If you need to run some operations as superuser, you can call Api::connectCompanion() to
    // get a socket to do IPC with a root companion process.
    // See Api::connectCompanion() for more info.
    virtual void preAppSpecialize([[maybe_unused]] AppSpecializeArgs *args) {}

    // This method is called after the app process is specialized.
    // At this point, the process has all sandbox restrictions enabled for this application.
    // If this method is called, it means this module's code is loaded into the target process
    // and will stay in memory until the process is terminated.
    // If you do not want your module to stay in memory after specialization, you can call
    // Api::setOption(DLCLOSE_MODULE_LIBRARY) in preAppSpecialize or postAppSpecialize.
    virtual void postAppSpecialize([[maybe_unused]] const AppSpecializeArgs *args) {}

    // This method is called before the system_server process is specialized.
    // See preAppSpecialize(AppSpecializeArgs) for more info.
    virtual void preServerSpecialize([[maybe_unused]] ServerSpecializeArgs *args) {}

    // This method is called after the system_server process is specialized.
    // See postAppSpecialize(AppSpecializeArgs) for more info.
    virtual void postServerSpecialize([[maybe_unused]] const ServerSpecializeArgs *args) {}
};

struct AppSpecializeArgs {
    // Required arguments. These arguments are guaranteed to exist on all Android versions.
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jobjectArray &rlimits;
    jint &mount_external;
    jstring &se_info;
    jstring &nice_name;
    jstring &instruction_set;
    jstring &app_data_dir;

    // Optional arguments. Please check whether the pointer is null before de-referencing.
    jintArray *gids_after_fork = nullptr;
    jboolean *is_child_zygote = nullptr;
    jboolean *is_top_app = nullptr;
    jobjectArray *pkg_data_info_list = nullptr;
    jobjectArray *whitelisted_data_info_list = nullptr;
    jboolean *mount_data_dirs = nullptr;
    jboolean *mount_storage_dirs = nullptr;
    jboolean *mount_sysprop_overrides = nullptr;

    AppSpecializeArgs() = delete;
};

struct ServerSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jlong &permitted_capabilities;
    jlong &effective_capabilities;

    ServerSpecializeArgs() = delete;
};

enum Option : int {
    // Force Magisk's denylist unmounting routines to run on this process.
    //
    // Setting this option only makes sense in preAppSpecialize.
    // The actual unmounting happens during app specialization.
    FORCE_DENYLIST_UNMOUNT = 0,

    // When this option is set, your module's library will be unloaded from
    // the process after postAppSpecialize.
    //
    // Setting this option only makes sense in preAppSpecialize or postAppSpecialize.
    // The actual dlclose() happens after postAppSpecialize.
    DLCLOSE_MODULE_LIBRARY = 1
};

// Bit masks of the return values of Api::getFlags()
enum StateFlag : uint32_t {
    // The user has granted root access to the current process
    PROCESS_GRANTED_ROOT = (1u << 0),

    // The current process was added on the denylist
    PROCESS_ON_DENYLIST = (1u << 1)
};

struct Api {

    // Connect to a root companion process and get a Unix domain socket for IPC.
    //
    // This framework is for providing root capabilities to modules that are running inside an
    // unprivileged app process. The companion process runs with root privilege in an isolated
    // SELinux context.
    //
    // Returns a file descriptor to a Unix domain socket that is connected to the socket passed to
    // the module's companion handler function. Returns -1 if the connection failed.
    int (*connectCompanion)(void *instance);

    // Get the path of the current module's directory.
    //
    // Returns a file descriptor to the module's directory. Returns -1 if the directory cannot
    // be opened or the module is unloaded.
    int (*getModuleDir)(void *instance);

    // Set various options for your module.
    // Please note that this function can only be called in preAppSpecialize or postAppSpecialize.
    void (*setOption)(void *instance, Option opt);

    // Get information about the current process.
    // Returns bitwise-or'd zygisk::StateFlag values.
    uint32_t (*getFlags)(void *instance);

    // Exempt the current process from unloading the module library.
    //
    // This function is only useful when the module is listed in the denylist.
    // Without calling this function, the module's library will be unloaded after
    // preAppSpecialize, and postAppSpecialize will NOT be called.
    void (*exemptFromDump)(void *instance);

    // Hook JNI native methods for a Java class.
    //
    // Looks up a registered JNI class and replaces its native methods with the ones provided
    // in `methods`. The original native method pointers will be saved in `methods`.
    void (*hookJniNativeMethods)(JNIEnv *env, const char *className, JNINativeMethod *methods, int numMethods);

    // For ELFs loaded in memory matching `dev` and `inode`, replace the function `symbol`
    // with `newFunc`. If `oldFunc` is not nullptr, the original function pointer will be saved
    // to `oldFunc`.
    void (*pltHookRegister)(dev_t dev, ino_t inode, const char *symbol, void *newFunc, void **oldFunc);

    // Commit all the hooks previously registered by pltHookRegister.
    bool (*pltHookCommit)(void);

    // Exempt a range of memory pages from PLT hooking.
    bool (*pltHookExclude)(dev_t dev, ino_t inode);

private:
    friend class ModuleBase;
    void *impl;
};

// Register a class as a Zygisk module
#define REGISTER_ZYGISK_MODULE(clazz) \
void zygisk_module_entry(void *impl, void *env) { \
    static clazz module; \
    module.onLoad(static_cast<zygisk::Api *>(impl), static_cast<JNIEnv *>(env)); \
} \
extern "C" [[gnu::visibility("default")]] void zygisk_entry(void *impl, void *env) { \
    zygisk_module_entry(impl, env); \
}

// Register a root companion handler function for your module
#define REGISTER_ZYGISK_COMPANION(func) \
void zygisk_companion_entry(int client) { \
    func(client); \
} \
extern "C" [[gnu::visibility("default")]] void zygisk_companion(int client) { \
    zygisk_companion_entry(client); \
}

} // namespace zygisk
