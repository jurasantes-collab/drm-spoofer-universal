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
static bool should_spoof = false;

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

static bool is_target_package(const char *pkg_name) {
    FILE *fp = fopen("/data/adb/modules/drm_spoofer_universal/target.txt", "r");
    if (fp == nullptr) return false;

    char line[LINE_LEN];
    bool matched = false;
    while (fgets(line, LINE_LEN, fp)) {
        if (line == '#' || line == '\n' || line == '\r') continue;
        size_t len = strcspn(line, "\r\n ");
        line[len] = '\0';
        if (len > 0 && strcmp(line, pkg_name) == 0) {
            matched = true;
            break;
        }
    }
    fclose(fp);
    return matched;
}

static void companion_handler(int client) {
    uint32_t pkg_len = 0;
    if (read(client, &pkg_len, sizeof(pkg_len)) != sizeof(pkg_len) || pkg_len == 0 || pkg_len >= LINE_LEN) {
        uint8_t allow = 0;
        write(client, &allow, 1);
        close(client);
        return;
    }

    char pkg_name[LINE_LEN];
    memset(pkg_name, 0, LINE_LEN);
    if (read(client, pkg_name, pkg_len) != static_cast<ssize_t>(pkg_len)) {
        uint8_t allow = 0;
        write(client, &allow, 1);
        close(client);
        return;
    }

    if (!is_target_package(pkg_name)) {
        uint8_t allow = 0;
        write(client, &allow, 1);
        close(client);
        return;
    }

    jbyte id_buf[ID_LEN];
    memset(id_buf, 0, ID_LEN);
    bool found = false;

    FILE *fp = fopen("/data/adb/modules/drm_spoofer_universal/drm.prop", "r");
    if (fp != nullptr) {
        char line[LINE_LEN];
        while (fgets(line, LINE_LEN, fp)) {
            if (line == '#' || line == '\n' || line == '\r') continue;
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

    uint8_t allow = 1;
    write(client, &allow, 1);
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
        if (args->nice_name == nullptr) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        // Ignora processos secundários (ex: com.app:service) pegando apenas o pacote base
        char base_pkg[LINE_LEN];
        size_t pkg_len = strcspn(process, ":");
        if (pkg_len >= LINE_LEN) pkg_len = LINE_LEN - 1;
        memcpy(base_pkg, process, pkg_len);
        base_pkg[pkg_len] = '\0';
        env->ReleaseStringUTFChars(args->nice_name, process);

        int fd = api->connectCompanion();
        if (fd >= 0) {
            uint32_t len32 = static_cast<uint32_t>(pkg_len);
            write(fd, &len32, sizeof(len32));
            write(fd, base_pkg, pkg_len);

            uint8_t allow = 0;
            if (read(fd, &allow, 1) == 1 && allow == 1) {
                if (read(fd, custom_drm_id, ID_LEN) == ID_LEN) {
                    should_spoof = true;
                }
            }
            close(fd);
        }

        // Remove completamente da memória RAM se não for o app alvo
        if (!should_spoof) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (!should_spoof) return;

        JNINativeMethod methods[] = {
            { "getPropertyByteArray", "(Ljava/lang/String;)[B", (void *)hooked_getPropertyByteArray }
        };

        api->hookJniNativeMethods(env, "android/media/MediaDrm", methods, 1);
        orig_getPropertyByteArray = reinterpret_cast<jbyteArray (*)(JNIEnv *, jobject, jstring)>(methods.fnPtr);
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
