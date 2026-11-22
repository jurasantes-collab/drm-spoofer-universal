#include <jni.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <fcntl.h>
#include <unistd.h>
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;

constexpr int ID_LEN = 32;
constexpr int LINE_LEN = 512;

static jbyteArray (*orig_getPropertyByteArray)(JNIEnv *env, jobject thiz, jstring propertyName) = nullptr;
static jbyte custom_drm_id[ID_LEN];
static bool drm_id_ready = false;

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void generate_random_id(jbyte *out) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t res = read(fd, out, ID_LEN);
        close(fd);
        if (res == ID_LEN) return;
    }
    for (int i = 0; i < ID_LEN; i++) {
        out[i] = static_cast<jbyte>(rand() & 0xFF);
    }
}

static void companion_handler(int client) {
    jbyte id_buf[ID_LEN];
    memset(id_buf, 0, ID_LEN);
    bool found = false;

    FILE *fp = fopen("/data/adb/modules/drm_spoofer_universal/drm.prop", "r");
    if (fp != nullptr) {
        char line[LINE_LEN];
        while (fgets(line, LINE_LEN, fp)) {
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
            if (strncmp(line, "drm_id=", 7) == 0) {
                char *val = line + 7;
                size_t len = strcspn(val, "\r\n");
                val[len] = '\0';

                if (len == ID_LEN * 2) {
                    bool all_hex = true;
                    for (int i = 0; i < ID_LEN; i++) {
                        int hi = hex_val(val[i * 2]);
                        int lo = hex_val(val[i * 2 + 1]);
                        if (hi < 0 || lo < 0) {
                            all_hex = false;
                            break;
                        }
                        id_buf[i] = static_cast<jbyte>((hi << 4) | lo);
                    }
                    if (all_hex) found = true;
                } else if (len > 0) {
                    size_t copy_len = len < ID_LEN ? len : ID_LEN;
                    memcpy(id_buf, val, copy_len);
                    found = true;
                }
                break;
            }
        }
        fclose(fp);
    }

    if (!found) {
        generate_random_id(id_buf);
    }

    write(client, id_buf, ID_LEN);
    close(client);
}

static jbyteArray hooked_getPropertyByteArray(JNIEnv *env, jobject thiz, jstring propertyName) {
    if (propertyName != nullptr) {
        const char *prop = env->GetStringUTFChars(propertyName, nullptr);
        if (prop != nullptr) {
            bool is_device_id = (strcmp(prop, "deviceUniqueId") == 0);
            env->ReleaseStringUTFChars(propertyName, prop);

            if (is_device_id) {
                if (!drm_id_ready) {
                    generate_random_id(custom_drm_id);
                    drm_id_ready = true;
                }
                jbyteArray result = env->NewByteArray(ID_LEN);
                if (result != nullptr) {
                    env->SetByteArrayRegion(result, 0, ID_LEN, custom_drm_id);
                }
                return result;
            }
        }
    }

    if (orig_getPropertyByteArray != nullptr &&
        orig_getPropertyByteArray != hooked_getPropertyByteArray) {
        return orig_getPropertyByteArray(env, thiz, propertyName);
    }
    return nullptr;
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
                env->ReleaseStringUTFChars(args->nice_name, process);
                return;
            }
            env->ReleaseStringUTFChars(args->nice_name, process);
        }

        int fd = api->connectCompanion(this);
        if (fd >= 0) {
            ssize_t r = read(fd, custom_drm_id, ID_LEN);
            close(fd);
            if (r == ID_LEN) {
                drm_id_ready = true;
            }
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process) {
            if (strcmp(process, "system_server") == 0 ||
                strncmp(process, "com.android.", 12) == 0) {
                env->ReleaseStringUTFChars(args->nice_name, process);
                return;
            }
            env->ReleaseStringUTFChars(args->nice_name, process);
        }

        JNINativeMethod methods[] = {
            { "getPropertyByteArray", "(Ljava/lang/String;)[B", (void *)hooked_getPropertyByteArray }
        };

        api->hookJniNativeMethods(env, "android/media/MediaDrm", methods, 1);
        orig_getPropertyByteArray = reinterpret_cast<jbyteArray (*)(JNIEnv *, jobject, jstring)>(methods[0].fnPtr);
        if (orig_getPropertyByteArray == hooked_getPropertyByteArray) {
            orig_getPropertyByteArray = nullptr;
        }
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(DrmSpooferModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
