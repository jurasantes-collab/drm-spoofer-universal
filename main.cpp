#include <jni.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include "zygisk.hpp"

// ATIVO APENAS PARA DIAGNOSTICO NO MATLOG (desative depois de achar o erro)
#define SPOOF_DEBUG

#ifdef SPOOF_DEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "SysCore", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "SysCore", __VA_ARGS__)
#else
#define LOGD(...) do {} while (0)
#define LOGE(...) do {} while (0)
#endif

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

namespace {

constexpr const char *kDefaultModDir = "/data/adb/modules/drm_spoofer_universal";
constexpr size_t kMaxPropLen = 91;

struct ScopedFd {
    int fd = -1;
    explicit ScopedFd(int f) : fd(f) {}
    ~ScopedFd() {
        if (fd >= 0) close(fd);
    }
    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;
};

inline void wipeString(std::string &s) {
    if (!s.empty()) {
        volatile char *p = const_cast<volatile char *>(s.data());
        for (size_t i = 0; i < s.size(); ++i) p[i] = 0;
        s.clear();
        s.shrink_to_fit();
    }
}

std::string trim(const std::string &in) {
    const size_t b = in.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const size_t e = in.find_last_not_of(" \t\r\n");
    return in.substr(b, e - b + 1);
}

std::string resolveModuleDir(Api *api) {
    if (!api) {
        LOGE("resolveModuleDir: api null, usando fallback %s", kDefaultModDir);
        return kDefaultModDir;
    }
    ScopedFd dir_guard(api->getModuleDir());
    if (dir_guard.fd < 0) {
        LOGE("resolveModuleDir: getModuleDir falhou (fd=%d, errno=%d), usando fallback %s",
             dir_guard.fd, errno, kDefaultModDir);
        return kDefaultModDir;
    }

    char fd_link[64];
    std::snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", dir_guard.fd);
    char resolved[256];
    const ssize_t n = readlink(fd_link, resolved, sizeof(resolved) - 1);
    if (n > 0) {
        resolved[n] = '\0';
        LOGD("resolveModuleDir: resolvido=%s", resolved);
        return std::string(resolved);
    }
    LOGE("resolveModuleDir: readlink falhou (errno=%d), usando fallback %s", errno, kDefaultModDir);
    return kDefaultModDir;
}

std::unordered_set<std::string> loadTargets(const std::string &path) {
    std::unordered_set<std::string> set;
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        LOGE("loadTargets: FALHA ao abrir %s (errno=%d)", path.c_str(), errno);
        return set;
    }

    std::string line;
    while (std::getline(ifs, line)) {
        const std::string c = trim(line);
        if (!c.empty() && c[0] != '#') set.insert(c);
    }
    LOGD("loadTargets: carregados %zu pacotes de %s", set.size(), path.c_str());
    return set;
}

std::unordered_map<std::string, std::string> loadKeyVals(const std::string &path) {
    std::unordered_map<std::string, std::string> map;
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        LOGE("loadKeyVals: FALHA ao abrir %s (errno=%d)", path.c_str(), errno);
        return map;
    }

    std::string line;
    while (std::getline(ifs, line)) {
        const std::string c = trim(line);
        if (c.empty() || c[0] == '#') continue;

        const size_t eq = c.find('=');
        if (eq == std::string::npos) continue;

        const std::string k = trim(c.substr(0, eq));
        const std::string v = trim(c.substr(eq + 1));
        if (!k.empty()) map[k] = v;
    }
    LOGD("loadKeyVals: carregadas %zu chaves de %s", map.size(), path.c_str());
    return map;
}

std::string generateHex32Bytes() {
    static constexpr char kHex[] = "0123456789abcdef";
    unsigned char raw[32];
    ScopedFd urandom(open("/dev/urandom", O_RDONLY | O_CLOEXEC));

    size_t filled = 0;
    if (urandom.fd >= 0) {
        while (filled < sizeof(raw)) {
            const ssize_t r = read(urandom.fd, raw + filled, sizeof(raw) - filled);
            if (r <= 0) break;
            filled += static_cast<size_t>(r);
        }
    }

    if (filled < sizeof(raw)) {
        std::srand(static_cast<unsigned int>(getpid()));
        for (size_t i = filled; i < sizeof(raw); ++i) {
            raw[i] = static_cast<unsigned char>(std::rand() & 0xFF);
        }
    }

    std::string out;
    out.reserve(64);
    for (unsigned char b : raw) {
        out.push_back(kHex[(b >> 4) & 0x0F]);
        out.push_back(kHex[b & 0x0F]);
    }
    std::memset(raw, 0, sizeof(raw));
    return out;
}

struct ActiveRuntimeState {
    std::mutex mtx;
    bool enabled = false;
    std::unordered_map<std::string, std::string> props;
    std::string drm_id;
};

ActiveRuntimeState &runtimeState() {
    static ActiveRuntimeState s;
    return s;
}

bool lookupOverrideLocked(const ActiveRuntimeState &st, const char *name, std::string &out_val) {
    if (!st.enabled || !name) return false;

    if (std::strcmp(name, "persist.sys.drm_id") == 0 || std::strcmp(name, "ro.drm.id") == 0) {
        if (!st.drm_id.empty()) {
            out_val = st.drm_id;
            return true;
        }
    }

    auto it = st.props.find(name);
    if (it != st.props.end() && !it->second.empty()) {
        out_val = it->second;
        return true;
    }
    return false;
}

int (*orig_system_property_get)(const char *name, char *value) = nullptr;

#if defined(__ANDROID_API__) && __ANDROID_API__ >= 29
void (*orig_system_property_read_callback)(
    const prop_info *pi,
    void (*callback)(void *cookie, const char *name, const char *value, uint32_t serial),
    void *cookie) = nullptr;
#endif

int hooked_system_property_get(const char *name, char *value) {
    if (!orig_system_property_get) return 0;

    if (name && value) {
        auto &st = runtimeState();
        std::lock_guard<std::mutex> lock(st.mtx);
        std::string override_val;
        if (lookupOverrideLocked(st, name, override_val)) {
            const size_t n = std::min(override_val.size(), kMaxPropLen);
            std::memcpy(value, override_val.data(), n);
            value[n] = '\0';
            LOGD("prop_get override: %s -> %s", name, value);
            wipeString(override_val);
            return static_cast<int>(n);
        }
    }
    return orig_system_property_get(name, value);
}

#if defined(__ANDROID_API__) && __ANDROID_API__ >= 29
void hooked_system_property_read_callback(
    const prop_info *pi,
    void (*callback)(void *cookie, const char *name, const char *value, uint32_t serial),
    void *cookie) {
    if (!orig_system_property_read_callback) return;
    if (!pi || !callback) {
        orig_system_property_read_callback(pi, callback, cookie);
        return;
    }

    char prop_name[PROP_NAME_MAX] = {0};
    char prop_val[PROP_VALUE_MAX] = {0};
    __system_property_read(pi, prop_name, prop_val);
    std::memset(prop_val, 0, sizeof(prop_val));

    if (prop_name[0] != '\0') {
        auto &st = runtimeState();
        std::lock_guard<std::mutex> lock(st.mtx);
        std::string override_val;
        if (lookupOverrideLocked(st, prop_name, override_val)) {
            char safe_val[PROP_VALUE_MAX] = {0};
            const size_t n = std::min(override_val.size(), kMaxPropLen);
            std::memcpy(safe_val, override_val.data(), n);
            safe_val[n] = '\0';
            wipeString(override_val);
            callback(cookie, prop_name, safe_val, 1);
            std::memset(safe_val, 0, sizeof(safe_val));
            return;
        }
    }

    orig_system_property_read_callback(pi, callback, cookie);
}
#endif

void applyJavaStringField(JNIEnv *env, jclass cls, const char *field, const std::string &val) {
    if (!env || !cls || val.empty()) return;
    jfieldID fid = env->GetStaticFieldID(cls, field, "Ljava/lang/String;");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("applyJavaStringField: GetStaticFieldID falhou para %s", field);
        return;
    }
    if (!fid) return;

    jstring jstr = env->NewStringUTF(val.c_str());
    if (jstr) {
        env->SetStaticObjectField(cls, fid, jstr);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            LOGE("applyJavaStringField: SetStaticObjectField falhou para %s", field);
        } else {
            LOGD("Build field alterado: %s = %s", field, val.c_str());
        }
        env->DeleteLocalRef(jstr);
    }
}

void applyJavaBuildSpoof(JNIEnv *env, const std::unordered_map<std::string, std::string> &props) {
    if (!env) {
        LOGE("applyJavaBuildSpoof: env null");
        return;
    }

    jclass build_cls = env->FindClass("android/os/Build");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("applyJavaBuildSpoof: FindClass android/os/Build falhou");
        return;
    }
    if (build_cls) {
        static constexpr const char *kBuildFields[] = {
            "MANUFACTURER", "MODEL", "FINGERPRINT", "BRAND", "PRODUCT",
            "DEVICE", "ID", "DISPLAY", "BOOTLOADER", "SERIAL", "TYPE", "TAGS"
        };
        for (const char *f : kBuildFields) {
            auto it = props.find(f);
            if (it != props.end()) applyJavaStringField(env, build_cls, f, it->second);
        }
        env->DeleteLocalRef(build_cls);
    }

    jclass ver_cls = env->FindClass("android/os/Build$VERSION");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("applyJavaBuildSpoof: FindClass Build$VERSION falhou");
        return;
    }
    if (ver_cls) {
        static constexpr const char *kVerFields[] = {
            "RELEASE", "INCREMENTAL", "SECURITY_PATCH"
        };
        for (const char *vf : kVerFields) {
            auto it = props.find(vf);
            if (it != props.end()) applyJavaStringField(env, ver_cls, vf, it->second);
        }
        env->DeleteLocalRef(ver_cls);
    }
}

} // namespace

class DrmSpooferModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
        LOGD("onLoad chamado (pid=%d, api=%p, env=%p)", getpid(), api_, env_);
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        clearStaging();
        if (!args || !args->nice_name || !env_) {
            LOGE("preAppSpecialize: args/nice_name/env invalido");
            return;
        }

        const char *raw = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (!raw) return;
        std::string pkg(raw);
        env_->ReleaseStringUTFChars(args->nice_name, raw);

        if (pkg.empty
