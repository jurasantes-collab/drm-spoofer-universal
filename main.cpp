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
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include "zygisk.hpp"

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

bool fileExists(const std::string &path) {
    std::ifstream ifs(path);
    return ifs.good();
}

std::string resolveModuleDir(Api *api) {
    if (!api) return kDefaultModDir;
    ScopedFd dir_guard(api->getModuleDir());
    if (dir_guard.fd < 0) return kDefaultModDir;

    char fd_link[64];
    std::snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", dir_guard.fd);
    char resolved[256];
    const ssize_t n = readlink(fd_link, resolved, sizeof(resolved) - 1);
    if (n > 0) {
        resolved[n] = '\0';
        return std::string(resolved);
    }
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
            wipeString(override_val);
            return static_cast<int>(n);
        }
    }
    return orig_system_property_get(name, value);
}

void injectDexAndApply(JNIEnv *env, const std::string &dex_path,
                       const std::unordered_map<std::string, std::string> &props) {
    if (!env || !fileExists(dex_path)) {
        LOGE("injectDexAndApply: dex ausente em %s", dex_path.c_str());
        return;
    }

    jclass cls_loader_cls = env->FindClass("java/lang/ClassLoader");
    jmethodID get_sys_loader = env->GetStaticMethodID(
        cls_loader_cls, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject sys_loader = env->CallStaticObjectMethod(cls_loader_cls, get_sys_loader);

    jclass path_loader_cls = env->FindClass("dalvik/system/PathClassLoader");
    jmethodID path_loader_init = env->GetMethodID(
        path_loader_cls, "<init>", "(Ljava/lang/String;Ljava/lang/ClassLoader;)V");

    jstring j_dex_path = env->NewStringUTF(dex_path.c_str());
    jobject dex_loader = env->NewObject(path_loader_cls, path_loader_init, j_dex_path, sys_loader);
    if (env->ExceptionCheck() || !dex_loader) {
        env->ExceptionClear();
        LOGE("injectDexAndApply: falha ao criar PathClassLoader");
        return;
    }

    jmethodID load_class = env->GetMethodID(
        cls_loader_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring j_cls_name = env->NewStringUTF("com.syscore.spoofer.SpoofEntry");
    jclass entry_cls = static_cast<jclass>(
        env->CallObjectMethod(dex_loader, load_class, j_cls_name));
    if (env->ExceptionCheck() || !entry_cls) {
        env->ExceptionClear();
        LOGE("injectDexAndApply: falha ao carregar SpoofEntry");
        return;
    }

    jmethodID apply_mid = env->GetStaticMethodID(
        entry_cls, "apply", "([Ljava/lang/String;[Ljava/lang/String;)V");
    if (env->ExceptionCheck() || !apply_mid) {
        env->ExceptionClear();
        LOGE("injectDexAndApply: metodo apply nao encontrado");
        return;
    }

    jclass str_cls = env->FindClass("java/lang/String");
    const jsize count = static_cast<jsize>(props.size());
    jobjectArray j_keys = env->NewObjectArray(count, str_cls, nullptr);
    jobjectArray j_vals = env->NewObjectArray(count, str_cls, nullptr);

    jsize idx = 0;
    for (const auto &kv : props) {
        jstring jk = env->NewStringUTF(kv.first.c_str());
        jstring jv = env->NewStringUTF(kv.second.c_str());
        env->SetObjectArrayElement(j_keys, idx, jk);
        env->SetObjectArrayElement(j_vals, idx, jv);
        env->DeleteLocalRef(jk);
        env->DeleteLocalRef(jv);
        ++idx;
    }

    env->CallStaticVoidMethod(entry_cls, apply_mid, j_keys, j_vals);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("injectDexAndApply: excecao dentro de SpoofEntry.apply");
    } else {
        LOGD("injectDexAndApply: classes.dex executado com sucesso");
    }

    env->DeleteLocalRef(j_keys);
    env->DeleteLocalRef(j_vals);
    env->DeleteLocalRef(str_cls);
    env->DeleteLocalRef(entry_cls);
    env->DeleteLocalRef(j_cls_name);
    env->DeleteLocalRef(dex_loader);
    env->DeleteLocalRef(j_dex_path);
    env->DeleteLocalRef(sys_loader);
    env->DeleteLocalRef(path_loader_cls);
    env->DeleteLocalRef(cls_loader_cls);
}

} // namespace

class DrmSpooferModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        clearStaging();
        if (!args || !args->nice_name || !env_) return;

        const char *raw = env_->GetStringUTFChars(args->nice_name, nullptr);
        if (!raw) return;
        std::string pkg(raw);
        env_->ReleaseStringUTFChars(args->nice_name, raw);
        if (pkg.empty()) return;

        mod_dir_ = resolveModuleDir(api_);
        const std::string cfg_target = mod_dir_ + "/config/target.txt";
        const std::string target_path = fileExists(cfg_target) ? cfg_target : (mod_dir_ + "/target.prop");

        const auto targets = loadTargets(target_path);
        if (targets.find(pkg) == targets.end()) {
            wipeString(pkg);
            return;
        }

        matched_ = true;
        const std::string cfg_prop = mod_dir_ + "/config/fix.prop";
        const std::string prop_path = fileExists(cfg_prop) ? cfg_prop : (mod_dir_ + "/device.prop");
        staged_props_ = loadKeyVals(prop_path);

        const auto drm_kv = loadKeyVals(mod_dir_ + "/drm.prop");
        auto it_drm = drm_kv.find("drm_id");
        staged_drm_ = (it_drm != drm_kv.end() && !it_drm->second.empty())
                          ? it_drm->second
                          : generateHex32Bytes();

        LOGD("Target matched: %s (props=%zu, prop_file=%s)",
             pkg.c_str(), staged_props_.size(), prop_path.c_str());
        wipeString(pkg);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        (void)args;
        if (!matched_) return;

        injectDexAndApply(env_, mod_dir_ + "/classes.dex", staged_props_);

        {
            auto &st = runtimeState();
            std::lock_guard<std::mutex> lock(st.mtx);
            st.props = std::move(staged_props_);
            st.drm_id = std::move(staged_drm_);
            st.enabled = true;
        }

        if (api_) {
            api_->pltHookRegister(".*", "__system_property_get",
                                  reinterpret_cast<void *>(&hooked_system_property_get),
                                  reinterpret_cast<void **>(&orig_system_property_get));
            bool ok = api_->pltHookCommit();
            LOGD("pltHookCommit=%d orig_get=%p", ok ? 1 : 0, orig_system_property_get);
        }

        clearStaging();
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override { (void)args; }
    void postServerSpecialize(const ServerSpecializeArgs *args) override { (void)args; }

private:
    void clearStaging() {
        matched_ = false;
        wipeString(staged_drm_);
        for (auto &kv : staged_props_) {
            std::string k = kv.first;
            std::string v = kv.second;
            wipeString(k);
            wipeString(v);
        }
        staged_props_.clear();
    }

    Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    bool matched_ = false;
    std::string mod_dir_;
    std::string staged_drm_;
    std::unordered_map<std::string, std::string> staged_props_;
};

REGISTER_ZYGISK_MODULE(DrmSpooferModule)
