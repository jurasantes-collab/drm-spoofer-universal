#include <jni.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <GLES2/gl2.h>
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;

constexpr int ID_LEN = 32;
constexpr int LINE_LEN = 512;

struct FullDeviceConfig {
    bool active = false;
    jbyte drm_id[ID_LEN];

    // Identidade
    char brand[64] = "samsung";
    char manufacturer[64] = "samsung";
    char model[64] = "SM-S928B";
    char device[64] = "e3q";
    char product[64] = "e3qxxx";
    char board[64] = "pineapple";
    char hardware[64] = "qcom";
    char bootloader[64] = "S928BXXU1AWM9";
    char fingerprint[256] = "samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXU1AWM9:user/release-keys";
    char build_id[64] = "UP1A.231005.007";
    char display_id[96] = "UP1A.231005.007.S928BXXU1AWM9";

    // Sistema & Kernel
    char android_version[32] = "14";
    int sdk_int = 34;
    char security_patch[32] = "2024-11-01";
    char kernel_release[128] = "6.1.75-android14-11-g8b2c4d9e1a0f";
    char kernel_version[128] = "#1 SMP PREEMPT Thu Oct 24 10:15:30 UTC 2024";

    // CPU
    char cpu_hardware[96] = "Qualcomm Technologies, Inc SM8650";
    char cpu_model_name[96] = "ARMv8 Processor rev 0 (v8l)";
    int cpu_cores = 8;
    char cpu_arch[32] = "aarch64";

    // GPU
    char gpu_vendor[64] = "Qualcomm";
    char gpu_renderer[96] = "Adreno (TM) 750";
    char gpu_version[96] = "OpenGL ES 3.2 V@0762.0";

    // RAM & Storage
    uint64_t ram_gb = 12;
    uint64_t storage_gb = 512;

    // Tela
    int screen_width = 1440;
    int screen_height = 3120;
    int screen_dpi = 600;
};

static FullDeviceConfig cfg;

// Ponteiros Originais
static jbyteArray (*orig_getPropertyByteArray)(JNIEnv *, jobject, jstring) = nullptr;
static void (*orig_getRealMetrics)(JNIEnv *, jobject, jobject) = nullptr;
static void (*orig_getMetrics)(JNIEnv *, jobject, jobject) = nullptr;

static int (*orig_sysinfo)(struct sysinfo *) = nullptr;
static int (*orig_statfs)(const char *, struct statfs *) = nullptr;
static int (*orig_uname)(struct utsname *) = nullptr;
static int (*orig_openat)(int, const char *, int, ...) = nullptr;
static FILE* (*orig_fopen)(const char *, const char *) = nullptr;
static const GLubyte* (*orig_glGetString)(GLenum) = nullptr;
static int (*orig_system_property_get)(const char *, char *) = nullptr;
static void (*orig_system_property_read_callback)(const prop_info *, void (*)(void *, const char *, const char *, uint32_t), void *) = nullptr;

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

// --- MAPA DE PROPRIEDADES NATIVAS & OCULTACAO LINEAGEOS ---

static const char* get_spoofed_prop(const char *name, char *temp_buf, size_t temp_size) {
    if (!name) return nullptr;

    // Oculta rastros de Custom ROM (LineageOS / Cyanogen / CrDroid / Evolution)
    if (strncmp(name, "ro.lineage.", 11) == 0 ||
        strncmp(name, "ro.cm.", 6) == 0 ||
        strncmp(name, "ro.modversion", 13) == 0 ||
        strncmp(name, "persist.lineage.", 16) == 0) {
        return "";
    }

    if (strcmp(name, "ro.build.tags") == 0 || strcmp(name, "ro.bootimage.build.tags") == 0) return "release-keys";
    if (strcmp(name, "ro.build.type") == 0 || strcmp(name, "ro.bootimage.build.type") == 0) return "user";
    if (strcmp(name, "ro.debuggable") == 0) return "0";
    if (strcmp(name, "ro.secure") == 0) return "1";
    if (strcmp(name, "ro.boot.flash.locked") == 0 || strcmp(name, "ro.boot.verifiedbootstate") == 0) {
        return (strcmp(name, "ro.boot.flash.locked") == 0) ? "1" : "green";
    }

    // Identidade
    if (strcmp(name, "ro.product.model") == 0 || strcmp(name, "ro.product.vendor.model") == 0 || strcmp(name, "ro.product.system.model") == 0) return cfg.model;
    if (strcmp(name, "ro.product.brand") == 0 || strcmp(name, "ro.product.vendor.brand") == 0 || strcmp(name, "ro.product.system.brand") == 0) return cfg.brand;
    if (strcmp(name, "ro.product.manufacturer") == 0 || strcmp(name, "ro.product.vendor.manufacturer") == 0) return cfg.manufacturer;
    if (strcmp(name, "ro.product.device") == 0 || strcmp(name, "ro.product.vendor.device") == 0) return cfg.device;
    if (strcmp(name, "ro.product.name") == 0 || strcmp(name, "ro.product.vendor.name") == 0) return cfg.product;
    if (strcmp(name, "ro.product.board") == 0 || strcmp(name, "ro.board.platform") == 0) return cfg.board;
    if (strcmp(name, "ro.hardware") == 0 || strcmp(name, "ro.hardware.chipname") == 0) return cfg.cpu_hardware;
    if (strcmp(name, "ro.bootloader") == 0 || strcmp(name, "ro.boot.bootloader") == 0) return cfg.bootloader;
    if (strcmp(name, "ro.build.fingerprint") == 0 || strcmp(name, "ro.system.build.fingerprint") == 0 || strcmp(name, "ro.vendor.build.fingerprint") == 0) return cfg.fingerprint;
    if (strcmp(name, "ro.build.id") == 0) return cfg.build_id;
    if (strcmp(name, "ro.build.display.id") == 0) return cfg.display_id;

    // Sistema Android
    if (strcmp(name, "ro.build.version.release") == 0 || strcmp(name, "ro.system.build.version.release") == 0) return cfg.android_version;
    if (strcmp(name, "ro.build.version.security_patch") == 0) return cfg.security_patch;
    if (strcmp(name, "ro.build.version.sdk") == 0 && temp_buf) {
        snprintf(temp_buf, temp_size, "%d", cfg.sdk_int);
        return temp_buf;
    }

    // CPU
    if (strcmp(name, "ro.product.cpu.abi") == 0) return cfg.cpu_arch;

    return nullptr;
}

static int hooked_system_property_get(const char *name, char *value) {
    char tmp[32];
    const char *spoof = get_spoofed_prop(name, tmp, sizeof(tmp));
    if (spoof != nullptr && value != nullptr) {
        strncpy(value, spoof, PROP_VALUE_MAX - 1);
        value[PROP_VALUE_MAX - 1] = '\0';
        return static_cast<int>(strlen(value));
    }
    return orig_system_property_get ? orig_system_property_get(name, value) : 0;
}

struct CallbackWrapper {
    void (*orig_cb)(void *, const char *, const char *, uint32_t);
    void *orig_cookie;
};

static void custom_prop_callback(void *cookie, const char *name, const char *value, uint32_t serial) {
    auto *wrap = static_cast<CallbackWrapper *>(cookie);
    char tmp[32];
    const char *spoof = get_spoofed_prop(name, tmp, sizeof(tmp));
    wrap->orig_cb(wrap->orig_cookie, name, spoof ? spoof : value, serial);
}

static void hooked_system_property_read_callback(const prop_info *pi, void (*callback)(void *, const char *, const char *, uint32_t), void *cookie) {
    if (!orig_system_property_read_callback) return;
    if (!pi || !callback) {
        orig_system_property_read_callback(pi, callback, cookie);
        return;
    }
    CallbackWrapper wrap{callback, cookie};
    orig_system_property_read_callback(pi, custom_prop_callback, &wrap);
}

// --- ARQUIVOS VIRTUAIS LEVES NA RAM (memfd_create) ---

static int create_fake_cpuinfo_fd() {
    int fd = static_cast<int>(syscall(__NR_memfd_create, "cpuinfo", 0));
    if (fd < 0) return -1;

    char buf[512];
    int cores = (cfg.cpu_cores > 0 && cfg.cpu_cores <= 16) ? cfg.cpu_cores : 8;
    for (int i = 0; i < cores; i++) {
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

static int create_fake_version_fd() {
    int fd = static_cast<int>(syscall(__NR_memfd_create, "version", 0));
    if (fd < 0) return -1;

    char buf[512];
    int len = snprintf(buf, sizeof(buf),
        "Linux version %s (build-user@build-host) (Android clang) %s\n",
        cfg.kernel_release, cfg.kernel_version);
    write(fd, buf, len);
    lseek(fd, 0, SEEK_SET);
    return fd;
}

// --- HOOKS DE SISTEMA E HARDWARE ---

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
        } else if (strcmp(pathname, "/proc/version") == 0) {
            int fd = create_fake_version_fd();
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
        } else if (strcmp(pathname, "/proc/version") == 0) {
            int fd = create_fake_version_fd();
            if (fd >= 0) return fdopen(fd, mode);
        }
    }
    return orig_fopen ? orig_fopen(pathname, mode) : nullptr;
}

static int hooked_uname(struct utsname *buf) {
    int ret = orig_uname ? orig_uname(buf) : -1;
    if (ret == 0 && buf) {
        if (strlen(cfg.kernel_release) > 0) {
            strncpy(buf->release, cfg.kernel_release, sizeof(buf->release) - 1);
            buf->release[sizeof(buf->release) - 1] = '\0';
        }
        if (strlen(cfg.kernel_version) > 0) {
            strncpy(buf->version, cfg.kernel_version, sizeof(buf->version) - 1);
            buf->version[sizeof(buf->version) - 1] = '\0';
        }
    }
    return ret;
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

// --- HOOKS JNI (BUILD JAVA, DRM E TELA) ---

static void set_static_string_field(JNIEnv *env, jclass cls, const char *field_name, const char *val) {
    if (!val || strlen(val) == 0) return;
    jfieldID fid = env->GetStaticFieldID(cls, field_name, "Ljava/lang/String;");
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }
    if (fid) {
        jstring jval = env->NewStringUTF(val);
        if (jval) {
            env->SetStaticObjectField(cls, fid, jval);
            env->DeleteLocalRef(jval);
        }
    }
}

static void spoof_java_build_fields(JNIEnv *env) {
    jclass build_cls = env->FindClass("android/os/Build");
    if (build_cls) {
        set_static_string_field(env, build_cls, "BRAND", cfg.brand);
        set_static_string_field(env, build_cls, "MANUFACTURER", cfg.manufacturer);
        set_static_string_field(env, build_cls, "MODEL", cfg.model);
        set_static_string_field(env, build_cls, "DEVICE", cfg.device);
        set_static_string_field(env, build_cls, "PRODUCT", cfg.product);
        set_static_string_field(env, build_cls, "BOARD", cfg.board);
        set_static_string_field(env, build_cls, "HARDWARE", cfg.cpu_hardware);
        set_static_string_field(env, build_cls, "BOOTLOADER", cfg.bootloader);
        set_static_string_field(env, build_cls, "FINGERPRINT", cfg.fingerprint);
        set_static_string_field(env, build_cls, "ID", cfg.build_id);
        set_static_string_field(env, build_cls, "DISPLAY", cfg.display_id);
        set_static_string_field(env, build_cls, "TAGS", "release-keys");
        set_static_string_field(env, build_cls, "TYPE", "user");
        env->DeleteLocalRef(build_cls);
    }

    jclass ver_cls = env->FindClass("android/os/Build$VERSION");
    if (ver_cls) {
        set_static_string_field(env, ver_cls, "RELEASE", cfg.android_version);
        set_static_string_field(env, ver_cls, "SECURITY_PATCH", cfg.security_patch);
        if (cfg.sdk_int > 0) {
            jfieldID sdk_fid = env->GetStaticFieldID(ver_cls, "SDK_INT", "I");
            if (env->ExceptionCheck()) { env->ExceptionClear(); }
            else if (sdk_fid) env->SetStaticIntField(ver_cls, sdk_fid, cfg.sdk_int);
        }
        env->DeleteLocalRef(ver_cls);
    }
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

// --- COMPANION (Leitura de Configs fora do processo do app) ---

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
    FullDeviceConfig local_cfg;
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
        char num[32];
        while (fgets(line, LINE_LEN, fp)) {
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

            parse_str(line, "brand", local_cfg.brand, sizeof(local_cfg.brand));
            parse_str(line, "manufacturer", local_cfg.manufacturer, sizeof(local_cfg.manufacturer));
            parse_str(line, "model", local_cfg.model, sizeof(local_cfg.model));
            parse_str(line, "device", local_cfg.device, sizeof(local_cfg.device));
            parse_str(line, "product", local_cfg.product, sizeof(local_cfg.product));
            parse_str(line, "board", local_cfg.board, sizeof(local_cfg.board));
            parse_str(line, "hardware", local_cfg.hardware, sizeof(local_cfg.hardware));
            parse_str(line, "bootloader", local_cfg.bootloader, sizeof(local_cfg.bootloader));
            parse_str(line, "fingerprint", local_cfg.fingerprint, sizeof(local_cfg.fingerprint));
            parse_str(line, "build_id", local_cfg.build_id, sizeof(local_cfg.build_id));
            parse_str(line, "display_id", local_cfg.display_id, sizeof(local_cfg.display_id));

            parse_str(line, "android_version", local_cfg.android_version, sizeof(local_cfg.android_version));
            parse_str(line, "security_patch", local_cfg.security_patch, sizeof(local_cfg.security_patch));
            parse_str(line, "kernel_release", local_cfg.kernel_release, sizeof(local_cfg.kernel_release));
            parse_str(line, "kernel_version", local_cfg.kernel_version, sizeof(local_cfg.kernel_version));

            parse_str(line, "cpu_hardware", local_cfg.cpu_hardware, sizeof(local_cfg.cpu_hardware));
            parse_str(line, "cpu_model_name", local_cfg.cpu_model_name, sizeof(local_cfg.cpu_model_name));
            parse_str(line, "cpu_arch", local_cfg.cpu_arch, sizeof(local_cfg.cpu_arch));
            parse_str(line, "gpu_vendor", local_cfg.gpu_vendor, sizeof(local_cfg.gpu_vendor));
            parse_str(line, "gpu_renderer", local_cfg.gpu_renderer, sizeof(local_cfg.gpu_renderer));
            parse_str(line, "gpu_version", local_cfg.gpu_version, sizeof(local_cfg.gpu_version));

            num[0] = '\0'; parse_str(line, "sdk_int", num, sizeof(num));
            if (num[0]) local_cfg.sdk_int = atoi(num);

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

        // Descarrega imediatamente da RAM se o app nao estiver no target.prop (Zero consumo e zero rastros)
        if (!cfg.active) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (!cfg.active) return;

        // 1. Altera campos estaticos Java (android.os.Build e Build.VERSION)
        spoof_java_build_fields(env);

        // 2. JNI Hook: DRM
        JNINativeMethod drm_methods[] = {
            { "getPropertyByteArray", "(Ljava/lang/String;)[B", (void *)hooked_getPropertyByteArray }
        };
        api->hookJniNativeMethods(env, "android/media/MediaDrm", drm_methods, 1);
        orig_getPropertyByteArray = reinterpret_cast<jbyteArray (*)(JNIEnv *, jobject, jstring)>(drm_methods[0].fnPtr);

        // 3. JNI Hook: Resolucao de Tela
        JNINativeMethod display_methods[] = {
            { "getRealMetrics", "(Landroid/util/DisplayMetrics;)V", (void *)hooked_getRealMetrics },
            { "getMetrics", "(Landroid/util/DisplayMetrics;)V", (void *)hooked_getMetrics }
        };
        api->hookJniNativeMethods(env, "android/view/Display", display_methods, 2);
        orig_getRealMetrics = reinterpret_cast<void (*)(JNIEnv *, jobject, jobject)>(display_methods[0].fnPtr);
        orig_getMetrics = reinterpret_cast<void (*)(JNIEnv *, jobject, jobject)>(display_methods[1].fnPtr);

        // 4. PLT Hooks: Propriedades Nativas, LineageOS, Kernel, CPU, GPU, RAM e Armazenamento
        api->pltHookRegister(".*", "__system_property_get", (void *)hooked_system_property_get, (void **)&orig_system_property_get);
        api->pltHookRegister(".*", "__system_property_read_callback", (void *)hooked_system_property_read_callback, (void **)&orig_system_property_read_callback);
        api->pltHookRegister(".*", "openat", (void *)hooked_openat, (void **)&orig_openat);
        api->pltHookRegister(".*", "fopen", (void *)hooked_fopen, (void **)&orig_fopen);
        api->pltHookRegister(".*", "uname", (void *)hooked_uname, (void **)&orig_uname);
        api->pltHookRegister(".*", "sysinfo", (void *)hooked_sysinfo, (void **)&orig_sysinfo);
        api->pltHookRegister(".*", "statfs", (void *)hooked_statfs, (void **)&orig_statfs);
        api->pltHookRegister(".*", "glGetString", (void *)hooked_glGetString, (void **)&orig_glGetString);
        api->pltHookCommit();
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(DrmSpooferModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
