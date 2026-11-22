#include <jni.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <GLES2/gl2.h>
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;

constexpr int ID_LEN = 32;
constexpr int LINE_LEN = 512;

struct HardwareConfig {
    bool active = false;
    jbyte drm_id[ID_LEN];

    uint64_t ram_gb = 12;
    uint64_t storage_gb = 512;

    char cpu_hardware[128] = "Qualcomm Technologies, Inc SM8650";
    char cpu_model_name[128] = "ARMv8 Processor rev 0 (v8l)";
    int cpu_cores = 8;
    char cpu_arch[64] = "aarch64";

    char gpu_vendor[128] = "Qualcomm";
    char gpu_renderer[128] = "Adreno (TM) 750";
    char gpu_version[128] = "OpenGL ES 3.2 V@0762.0";

    int screen_width = 1440;
    int screen_height = 3120;
    int screen_dpi = 600;
};

static HardwareConfig cfg;

static jbyteArray (*orig_getPropertyByteArray)(JNIEnv *, jobject, jstring) = nullptr;
static void (*orig_getRealMetrics)(JNIEnv *, jobject, jobject) = nullptr;
static void (*orig_getMetrics)(JNIEnv *, jobject, jobject) = nullptr;

static int (*orig_sysinfo)(struct sysinfo *) = nullptr;
static int (*orig_statfs)(const char *, struct statfs *) = nullptr;
static int (*orig_openat)(int, const char *, int, ...) = nullptr;
static FILE* (*orig_fopen)(const char *, const char *) = nullptr;
static const GLubyte* (*orig_glGetString)(GLenum) = nullptr;
static int (*orig_system_property_get)(const char *, char *) = nullptr;

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void generate_random_id(jbyte *out) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, out, ID_LEN) == ID_LEN) { close(fd); return; }
        close(fd);
    }
    for (int i = 0; i < ID_LEN; i++) out[i] = static_cast<jbyte>(rand() & 0xFF);
}

static int create_fake_cpuinfo_fd() {
    int fd = static_cast<int>(syscall(__NR_memfd_create, "cpuinfo", 0));
    if (fd < 0) return -1;

    char buf[512];
    for (int i = 0; i < cfg.cpu_cores; i++) {
        int len = snprintf(buf, sizeof(buf),
            "processor\t: %d\n"
            "model name\t: %s\n"
            "BogoMIPS\t: 38.40\n"
            "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
            "CPU implementer\t: 0x41\n"
            "CPU architecture: 8\n"
            "CPU variant\t: 0x1\n"
            "CPU part\t: 0xd80\n"
            "CPU revision\t: 0\n\n",
            i, cfg.cpu_model_name);
        write(fd, buf, len);
    }
    int tail_len = snprintf(buf, sizeof(buf), "Hardware\t: %s\n", cfg.cpu_hardware);
    write(fd, buf, tail_len);
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static int create_fake_meminfo_fd() {
    int fd = static_cast<int>(syscall(__NR_memfd_create, "meminfo", 0));
    if (fd < 0) return -1;

    uint64_t total_kb = cfg.ram_gb * 1024ULL * 1024ULL;
    uint64_t free_kb = total_kb / 3;
    uint64_t avail_kb = (total_kb * 2) / 3;

    char buf[512];
    int len = snprintf(buf, sizeof(buf),
        "MemTotal:       %llu kB\n"
        "MemFree:        %llu kB\n"
        "MemAvailable:   %llu kB\n"
        "Buffers:          131072 kB\n"
        "Cached:          2097152 kB\n"
        "SwapTotal:       4194304 kB\n"
        "SwapFree:        4194304 kB\n",
        static_cast<unsigned long long>(total_kb),
        static_cast<unsigned long long>(free_kb),
        static_cast<unsigned long long>(avail_kb));
    write(fd, buf, len);
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static int hooked_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (pathname) {
        if (strcmp(pathname, "/proc/cpuinfo") == 0) {
            int fd = create_fake_cpuinfo_fd();
            if (fd >= 0) return fd;
        } else if (strcmp(pathname, "/proc/meminfo") == 0 && cfg.ram_gb > 0) {
            int fd = create_fake_meminfo_fd();
            if (fd >= 0) return fd;
        }
    }

    return orig_openat ? orig_openat(dirfd, pathname, flags, mode) : -1;
}

static FILE* hooked_fopen(const char *pathname, const char *mode) {
    if (pathname && mode && strchr(mode, 'r')) {
        if (strcmp(pathname, "/proc/cpuinfo") == 0) {
            int fd = create_fake_cpuinfo_fd();
            if (fd >= 0) return fdopen(fd, mode);
        } else if (strcmp(pathname, "/proc/meminfo") == 0 && cfg.ram_gb > 0) {
            int fd = create_fake_meminfo_fd();
            if (fd >= 0) return fdopen(fd, mode);
        }
    }
    return orig_fopen ? orig_fopen(pathname, mode) : nullptr;
}

static int hooked_sysinfo(struct sysinfo *info) {
    int ret = orig_sysinfo ? orig_sysinfo(info) : -1;
    if (ret == 0 && info && cfg.ram_gb > 0) {
        uint64_t target_bytes = cfg.ram_gb * 1024ULL * 1024ULL * 1024ULL;
        double ratio = static_cast<double>(info->freeram) / (info->totalram > 0 ? info->totalram : 1);
        info->mem_unit = 1;
        info->totalram = target_bytes;
        info->freeram = static_cast<uint64_t>(target_bytes * ratio);
    }
    return ret;
}

static int hooked_statfs(const char *path, struct statfs *buf) {
    int ret = orig_statfs ? orig_statfs(path, buf) : -1;
    if (ret == 0 && buf && path && (strncmp(path, "/data", 5) == 0 || strncmp(path, "/storage", 8) == 0) && cfg.storage_gb > 0) {
        uint64_t bsize = buf->f_bsize > 0 ? buf->f_bsize : 4096;
        uint64_t target_blocks = (cfg.storage_gb * 1024ULL * 1024ULL * 1024ULL) / bsize;
        double free_ratio = static_cast<double>(buf->f_bfree) / (buf->f_blocks > 0 ? buf->f_blocks : 1);
        buf->f_blocks = target_blocks;
        buf->f_bfree = static_cast<uint64_t>(target_blocks * free_ratio);
        buf->f_bavail = buf->f_bfree;
    }
    return ret;
}

static const GLubyte* hooked_glGetString(GLenum name) {
    if (name == GL_VENDOR && strlen(cfg.gpu_vendor) > 0)
        return reinterpret_cast<const GLubyte*>(cfg.gpu_vendor);
    if (name == GL_RENDERER && strlen(cfg.gpu_renderer) > 0)
        return reinterpret_cast<const GLubyte*>(cfg.gpu_renderer);
    if (name == GL_VERSION && strlen(cfg.gpu_version) > 0)
        return reinterpret_cast<const GLubyte*>(cfg.gpu_version);
    return orig_glGetString ? orig_glGetString(name) : nullptr;
}

static int hooked_system_property_get(const char *name, char *value) {
    if (name && value) {
        const char *spoof = nullptr;
        if (strcmp(name, "ro.board.platform") == 0 || strcmp(name, "ro.hardware") == 0) {
            spoof = cfg.cpu_hardware;
        } else if (strcmp(name, "ro.product.cpu.abi") == 0) {
            spoof = cfg.cpu_arch;
        }
        if (spoof && strlen(spoof) > 0) {
            strcpy(value, spoof);
            return static_cast<int>(strlen(spoof));
        }
    }
    return orig_system_property_get ? orig_system_property_get(name, value) : 0;
}

static jbyteArray hooked_getPropertyByteArray(JNIEnv *env, jobject thiz, jstring propertyName) {
    if (propertyName != nullptr) {
        const char *prop = env->GetStringUTFChars(propertyName, nullptr);
        if (prop != nullptr) {
            bool is_id = (strcmp(prop, "deviceUniqueId") == 0);
            env->ReleaseStringUTFChars(propertyName, prop);
            if (is_id) {
                jbyteArray res = env->NewByteArray(ID_LEN);
                if (res) env->SetByteArrayRegion(res, 0, ID_LEN, cfg.drm_id);
                return res;
            }
        }
    }
    return orig_getPropertyByteArray ? orig_getPropertyByteArray(env, thiz, propertyName) : nullptr;
}

static void apply_fake_metrics(JNIEnv *env, jobject metrics) {
    if (!metrics || cfg.screen_width <= 0 || cfg.screen_height <= 0) return;
    jclass cls = env->GetObjectClass(metrics);
    if (!cls) return;

    jfieldID wField = env->GetFieldID(cls, "widthPixels", "I");
    jfieldID hField = env->GetFieldID(cls, "heightPixels", "I");
    jfieldID dpiField = env->GetFieldID(cls, "densityDpi", "I");
    jfieldID densField = env->GetFieldID(cls, "density", "F");
    jfieldID scaledField = env->GetFieldID(cls, "scaledDensity", "F");

    if (wField) env->SetIntField(metrics, wField, cfg.screen_width);
    if (hField) env->SetIntField(metrics, hField, cfg.screen_height);
    if (cfg.screen_dpi > 0) {
        float density = static_cast<float>(cfg.screen_dpi) / 160.0f;
        if (dpiField) env->SetIntField(metrics, dpiField, cfg.screen_dpi);
        if (densField) env->SetFloatField(metrics, densField, density);
        if (scaledField) env->SetFloatField(metrics, scaledField, density);
    }
    env->DeleteLocalRef(cls);
}

static void hooked_getRealMetrics(JNIEnv *env, jobject thiz, jobject outMetrics) {
    if (orig_getRealMetrics) orig_getRealMetrics(env, thiz, outMetrics);
    apply_fake_metrics(env, outMetrics);
}

static void hooked_getMetrics(JNIEnv *env, jobject thiz, jobject outMetrics) {
    if (orig_getMetrics) orig_getMetrics(env, thiz, outMetrics);
    apply_fake_metrics(env, outMetrics);
}

static bool is_target_package(const char *pkg_name) {
    FILE *fp = fopen("/data/adb/modules/drm_spoofer_universal/target.prop", "r");
    if (!fp) return false;
    char line[LINE_LEN];
    bool matched = false;
    while (fgets(line, LINE_LEN, fp)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        size_t len = strcspn(line, "\r\n ");
        line[len] = '\0';
        if (len > 0 && strcmp(line, pkg_name) == 0) { matched = true; break; }
    }
    fclose(fp);
    return matched;
}

static void parse_str(char *line, const char *key, char *dest, size_t max_len) {
    size_t klen = strlen(key);
    if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
        char *val = line + klen + 1;
        val[strcspn(val, "\r\n")] = '\0';
        strncpy(dest, val, max_len - 1);
        dest[max_len - 1] = '\0';
    }
}

static void companion_handler(int client) {
    HardwareConfig local_cfg;
    uint32_t pkg_len = 0;
    if (read(client, &pkg_len, sizeof(pkg_len)) != sizeof(pkg_len) || pkg_len == 0 || pkg_len >= LINE_LEN) {
        write(client, &local_cfg, sizeof(local_cfg)); close(client); return;
    }

    char pkg_name[LINE_LEN] = {0};
    if (read(client, pkg_name, pkg_len) != static_cast<ssize_t>(pkg_len) || !is_target_package(pkg_name)) {
        write(client, &local_cfg, sizeof(local_cfg)); close(client); return;
    }

    local_cfg.active = true;
    bool drm_found = false;

    FILE *fp = fopen("/data/adb/modules/drm_spoofer_universal/drm.prop", "r");
    if (fp) {
        char line[LINE_LEN];
        while (fgets(line, LINE_LEN, fp)) {
            if (strncmp(line, "drm_id=", 7) == 0) {
                char *val = line + 7;
                size_t len = strcspn(val, "\r\n");
                val[len] = '\0';
                if (len == ID_LEN * 2) {
                    bool ok = true;
                    for (int i = 0; i < ID_LEN; i++) {
                        int hi = hex_val(val[i * 2]), lo = hex_val(val[i * 2 + 1]);
                        if (hi < 0 || lo < 0) { ok = false; break; }
                        local_cfg.drm_id[i] = static_cast<jbyte>((hi << 4) | lo);
                    }
                    if (ok) drm_found = true;
                }
                break;
            }
        }
        fclose(fp);
    }
    if (!drm_found) generate_random_id(local_cfg.drm_id);

    fp = fopen("/data/adb/modules/drm_spoofer_universal/device.prop", "r");
    if (fp) {
        char line[LINE_LEN];
        char num[64];
        while (fgets(line, LINE_LEN, fp)) {
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

            parse_str(line, "cpu_hardware", local_cfg.cpu_hardware, sizeof(local_cfg.cpu_hardware));
            parse_str(line, "cpu_model_name", local_cfg.cpu_model_name, sizeof(local_cfg.cpu_model_name));
            parse_str(line, "cpu_arch", local_cfg.cpu_arch, sizeof(local_cfg.cpu_arch));
            parse_str(line, "gpu_vendor", local_cfg.gpu_vendor, sizeof(local_cfg.gpu_vendor));
            parse_str(line, "gpu_renderer", local_cfg.gpu_renderer, sizeof(local_cfg.gpu_renderer));
            parse_str(line, "gpu_version", local_cfg.gpu_version, sizeof(local_cfg.gpu_version));

            num[0] = '\0'; parse_str(line, "ram_gb", num, sizeof(num));
            if (num[0]) local_cfg.ram_gb = strtoull(num, nullptr, 10);

            num[0] = '\0'; parse_str(line, "storage_gb", num, sizeof(num));
            if (num[0]) local_cfg.storage_gb = strtoull(num, nullptr, 10);

            num[0] = '\0'; parse_str(line, "cpu_cores", num, sizeof(num));
            if (num[0]) local_cfg.cpu_cores = atoi(num);

            num[0] = '\0'; parse_str(line, "screen_width", num, sizeof(num));
            if (num[0]) local_cfg.screen_width = atoi(num);

            num[0] = '\0'; parse_str(line, "screen_height", num, sizeof(num));
            if (num[0]) local_cfg.screen_height = atoi(num);

            num[0] = '\0'; parse_str(line, "screen_dpi", num, sizeof(num));
            if (num[0]) local_cfg.screen_dpi = atoi(num);
        }
        fclose(fp);
    }

    write(client, &local_cfg, sizeof(local_cfg));
    close(client);
}

class DrmSpooferModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (!args->nice_name) { api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); return; }
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!process) { api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); return; }

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
            read(fd, &cfg, sizeof(cfg));
            close(fd);
        }

        if (!cfg.active) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (!cfg.active) return;

        JNINativeMethod drm_methods[] = {
            { "getPropertyByteArray", "(Ljava/lang/String;)[B", (void *)hooked_getPropertyByteArray }
        };
        api->hookJniNativeMethods(env, "android/media/MediaDrm", drm_methods, 1);
        orig_getPropertyByteArray = reinterpret_cast<jbyteArray (*)(JNIEnv *, jobject, jstring)>(drm_methods[0].fnPtr);

        JNINativeMethod display_methods[] = {
            { "getRealMetrics", "(Landroid/util/DisplayMetrics;)V", (void *)hooked_getRealMetrics },
            { "getMetrics", "(Landroid/util/DisplayMetrics;)V", (void *)hooked_getMetrics }
        };
        api->hookJniNativeMethods(env, "android/view/Display", display_methods, 2);
        orig_getRealMetrics = reinterpret_cast<void (*)(JNIEnv *, jobject, jobject)>(display_methods[0].fnPtr);
        orig_getMetrics = reinterpret_cast<void (*)(JNIEnv *, jobject, jobject)>(display_methods[1].fnPtr);

        api->pltHookRegister(".*", "openat", (void *)hooked_openat, (void **)&orig_openat);
        api->pltHookRegister(".*", "fopen", (void *)hooked_fopen, (void **)&orig_fopen);
        api->pltHookRegister(".*", "sysinfo", (void *)hooked_sysinfo, (void **)&orig_sysinfo);
        api->pltHookRegister(".*", "statfs", (void *)hooked_statfs, (void **)&orig_statfs);
        api->pltHookRegister(".*", "glGetString", (void *)hooked_glGetString, (void **)&orig_glGetString);
        api->pltHookRegister(".*", "__system_property_get", (void *)hooked_system_property_get, (void **)&orig_system_property_get);
        api->pltHookCommit();
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(DrmSpooferModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
