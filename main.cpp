#include <jni.h>
#include <android/log.h>
#include "zygisk.hpp"

#define LOG_TAG "DrmSpoofer"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

class DrmSpooferModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        LOGD("DrmSpooferModule carregado (API %d)", ZYGISK_API_VERSION);
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        (void)args;
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        (void)args;
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        (void)args;
    }

    void postServerSpecialize(const ServerSpecializeArgs *args) override {
        (void)args;
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(DrmSpooferModule)
