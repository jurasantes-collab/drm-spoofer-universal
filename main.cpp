#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

static int (*orig_system_property_get)(const char *name, char *value) = nullptr;

static int hooked_system_property_get(const char *name, char *value) {
    int res = orig_system_property_get ? orig_system_property_get(name, value) : 0;
    if (name && value) {
        if (strcmp(name, "drm.service.enabled") == 0) {
            strcpy(value, "true");
            return strlen(value);
        }
        if (strcmp(name, "ro.drm.widevine.level") == 0 ||
            strcmp(name, "persist.vendor.sys.widevine.level") == 0) {
            strcpy(value, "1");
            return strlen(value);
        }
        if (strcmp(name, "ro.product.model") == 0) {
            strcpy(value, "Pixel 8 Pro");
            return strlen(value);
        }
        if (strcmp(name, "ro.product.manufacturer") == 0 ||
            strcmp(name, "ro.product.brand") == 0) {
            strcpy(value, "Google");
            return strlen(value);
        }
    }
    return res;
}

class DrmSpooferModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process) {
            if (strcmp(process, "system_server") == 0 ||
                strncmp(process, "com.android.", 12) == 0) {
                api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                env->ReleaseStringUTFChars(args->nice_name, process);
                return;
            }
            env->ReleaseStringUTFChars(args->nice_name, process);
        }

        ino_t inode = 0;
        dev_t dev = 0;
        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line;
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "libc.so")) {
                    unsigned int major = 0, minor = 0;
                    unsigned long ino = 0;
                    if (sscanf(line, "%*x-%*x %*s %*x %x:%x %lu", &major, &minor, &ino) == 3) {
                        dev = makedev(major, minor);
                        inode = ino;
                        break;
                    }
                }
            }
            fclose(fp);
        }

        if (inode != 0) {
            api->pltHookRegister(dev, inode, "__system_property_get",
                                 (void *)hooked_system_property_get,
                                 (void **)&orig_system_property_get);
            api->pltHookCommit();
        }
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(DrmSpooferModule)

         
            
        
