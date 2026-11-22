#include <jni.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/sysinfo.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/system_properties.h>
#include <GLES2/gl2.h>
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;

constexpr int ID_LEN = 32;
constexpr int LINE_LEN = 512;
constexpr int MAX_PROPS = 180;

struct PropEntry {
    char key[96];
    char val[192];
};

struct FullConfig {
    bool active = false;
    jbyte drm_id[ID_LEN];

    // Java Build Fields
    char b_manufacturer[64] = "samsung";
    char b_model[64] = "SM-N9600";
    char b_fingerprint[256] = "samsung/crownqlteub/crownqlte:9/PPR1.180610.011/N9600ZHS4CSL2:user/release-keys";
    char b_brand[64] = "samsung";
    char b_product[64] = "crownqlteub";
    char b_device[64] = "crownqlte";
    char b_board[64] = "sdm845";
    char b_hardware[64] = "qcom";
    char b_release[32] = "9";
    char b_id[64] = "PPR1.180610.011";
    char b_display[128] = "PPR1.180610.011.N9600ZHS4CSL2";
    char b_incremental[64] = "N9600ZHS4CSL2";
    char b_bootloader[64] = "N9600ZHS4CSL2";
    char b_serial[64] = "R58K914728N";
    char b_type[32] = "user";
    char b_tags[64] = "release-keys";
    char b_security_patch[32] = "2019-12-01";
    int64_t b_time = 1576769410000LL;
    int b_sdk_int = 28;
    int b_first_sdk = 27;

    // Wildcards
    char wc_build_id[64] = "PPR1.180610.011";
    char wc_security_patch[32] = "2019-12-01";
    char wc_api_level[16] = "27";

    // Hardware & Kernel
    char kernel_release[128] = "4.9.112-17257921";
    char kernel_version[192] = "#1 SMP PREEMPT Thu Dec 19 15:30:10 KST 2019";
    char cpu_hardware[128] = "Qualcomm Technologies, Inc SDM845";
    char cpu_model_name[128] = "ARMv8 Processor rev 12 (v8l)";
    int cpu_cores = 8;
    char cpu_arch[32] = "aarch64";
    char gpu_vendor[64] = "Qualcomm";
    char gpu_renderer[128] = "Adreno (TM) 630";
    char gpu_version[128] = "OpenGL ES 3.2 V@331.0";
    uint64_t ram_gb = 6;
    uint64_t storage_gb = 128;
    int screen_width = 1440;
    int screen_height = 2960;
    int screen_dpi = 560;

    // Dynamic ro.* properties
    int prop_count = 0;
    PropEntry props[MAX_PROPS];
};

static FullConfig cfg;

// Original function pointers
static jbyteArray (*orig_getPropertyByteArray)(JNIEnv *, jobject, jstring) = nullptr;
static jstring (*orig_getSerial)(JNIEnv *, jclass) = nullptr;
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

// --- HELPERS ---

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

static bool ends_with(const char *str, const char *suffix) {
    size_t slen = strlen(str), suflen = strlen(suffix);
    return slen >= suflen && strcmp(str + slen - suflen, suffix) == 0;
}

static const char* lookup_spoof_prop(const char *name) {
    if (!name) return nullptr;

    // Bloqueia rastros de Custom ROMs
    if (strncmp(name, "ro.lineage.", 11) == 0 ||
        strncmp(name, "ro.crdroid.", 11) == 0 ||
        strncmp(name, "ro.evolution.", 13) == 0 ||
        strncmp(name, "ro.arrow.", 9) == 0 ||
        strncmp(name, "ro.havoc.", 9) == 0 ||
        strncmp(name, "ro.bliss.", 9) == 0 ||
        strncmp(name, "ro.pixelexperience.", 19) == 0 ||
        strcmp(name, "ro.modversion") == 0 ||
        strcmp(name, "ro.rom.version") == 0) {
        return "";
    }

    // Busca exata na lista dinamica
    for (int i = 0; i < cfg.prop_count; i++) {
        if (strcmp(cfg.props[i].key, name) == 0) {
            return cfg.props[i].val;
        }
    }

    // Wildcards
    if (strlen(cfg.wc_build_id) > 0 && ends_with(name, ".build.id")) return cfg.wc_build_id;
    if (strlen(cfg.wc_security_patch) > 0 && ends_with(name, ".security_patch")) return cfg.wc_security_patch;
    if (strlen(cfg.wc_api_level) > 0 && ends_with(name, "api_level")) return cfg.wc_api_level;

    return nullptr;
}

// --- VIRTUAL FILES (memfd) ---

static int create_memfd_text(const char *name, const char *text) {
    int fd = static_cast<int>(syscall(__NR_memfd_create, name, 0));
    if (fd < 0) return -1;
    write(fd, text, strlen(text));
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static int create_fake_cpuinfo_fd() {
    int fd = static_cast<int>(syscall(__NR_memfd_create, "cpuinfo", 0));
    if (fd < 0) return -1;
    char buf[512];
    for (int i = 0; i < cfg.cpu_cores; i++) {
        int len = snprintf(buf, sizeof(buf),
            "processor	: %d
"
            "model name	: %s
"
            "BogoMIPS	: 38.40
"
            "Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics
"
            "CPU implementer	: 0x51
"
            "CPU architecture: 8
"
            "CPU variant	: 0x7
"
            "CPU part	: 0x802
"
            "CPU revision	: 12

",
            i, cfg.cpu_model_name);
        write(fd, buf, len);
    }
    int tlen = snprintf(buf, sizeof(buf), "Hardware	: %s
", cfg.cpu_hardware);
    write(fd, buf, tlen);
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static int create_fake_meminfo_fd() {
    uint64_t total_kb = cfg.ram_gb * 1024ULL * 1024ULL;
    char buf[512];
    snprintf(buf, sizeof(buf),
        "MemTotal:       %llu kB
"
        "MemFree:        %llu kB
"
        "MemAvailable:   %llu kB
"
        "Buffers:          131072 kB
"
        "Cached:          1572864 kB
"
        "SwapTotal:       2097152 kB
"
        "SwapFree:        2097152 kB
",
        static_cast<unsigned long long>(total_kb),
        static_cast<unsigned long long>(total_kb / 3),
        static_cast<unsigned long long>((total_kb * 2) / 3));
    return create_memfd_text("meminfo", buf);
}

static int create_fake_version_fd() {
    char buf[512];
    snprintf(buf, sizeof(buf),
        "Linux version %s (dpi@SWDH8411) (gcc version 4.9.x 20150123 (prerelease) (GCC)) %s
",
        cfg.kernel_release, cfg.kernel_version);
    return create_memfd_text("version", buf);
}

// --- NATIVE HOOKS ---

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
        } else if (strcmp(pathname, "/sys/fs/selinux/enforce") == 0) {
            int fd = create_memfd_text("enforce", "1");
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
        } else if (strcmp(pathname, "/sys/fs/selinux/enforce") == 0) {
            int fd = create_memfd_text("enforce", "1");
            if (fd >= 0) return fdopen(fd, mode);
        }
    }
    return orig_fopen ? orig_fopen(pathname, mode) : nullptr;
}

static int hooked_uname(struct utsname *buf) {
    int ret = orig_uname ? orig_uname(buf) : -1;
    if (ret == 0 && buf) {
        strncpy(buf->release, cfg.kernel_release, sizeof(buf->release) - 1);
        buf->release[sizeof(buf->release) - 1] = '�';
        strncpy(buf->version, cfg.kernel_version, sizeof(buf->version) - 1);
        buf->version[sizeof(buf->version) - 1] = '�';
        strncpy(buf->machine, cfg.cpu_arch, sizeof(buf->machine) - 1);
        buf->machine[sizeof(buf->machine) - 1] = '�';
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

static int hooked_system_property_get(const char *name, char *value) {
    if (name && value) {
        const char *spoof = lookup_spoof_prop(name);
        if (spoof != nullptr) {
            strncpy(value, spoof, PROP_VALUE_MAX - 1);
            value[PROP_VALUE_MAX - 1] = '�';
            return static_cast<int>(strlen(value));
        }
    }
    return orig_system_property_get ? orig_system_property_get(name, value) : 0;
}

struct PropCallbackCtx {
    void (*orig_cb)(void *cookie, const char *name, const char *value, uint32_t serial);
    void *orig_cookie;
};

static void custom_prop_callback(void *cookie, const char *name, const char *value, uint32_t serial) {
    auto *ctx = static_cast<PropCallbackCtx *>(cookie);
    const char *spoof = lookup_spoof_prop(name);
    if (spoof != nullptr) {
        ctx->orig_cb(ctx->orig_cookie, name, spoof, serial);
    } else {
        ctx->orig_cb(ctx->orig_cookie, name, value, serial);
    }
}

static void hooked_system_property_read_callback(
    const prop_info *pi,
    void (*callback)(void *cookie, const char *name, const char *value, uint32_t serial),
    void *cookie) {
    if (orig_system_property_read_callback && callback) {
        PropCallbackCtx ctx{callback, cookie};
        orig_system_property_read_callback(pi, custom_prop_callback, &ctx);
    }
}

// --- JNI HOOKS (Build, Display & MediaDrm) ---

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

static jstring hooked_getSerial(JNIEnv *env, jclass clazz) {
    if (strlen(cfg.b_serial) > 0) {
        return env->NewStringUTF(cfg.b_serial);
    }
    return orig_getSerial ? orig_getSerial(env, clazz) : nullptr;
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

static void set_static_str(JNIEnv *env, jclass cls, const char *field_name, const char *val) {
    if (!cls || !val || strlen(val) == 0) return;
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

static void set_static_int(JNIEnv *env, jclass cls, const char *field_name, jint val) {
    if (!cls || val <= 0) return;
    jfieldID fid = env->GetStaticFieldID(cls, field_name, "I");
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }
    if (fid) env->SetStaticIntField(cls, fid, val);
}

static void set_static_long(JNIEnv *env, jclass cls, const char *field_name, jlong val) {
    if (!cls || val <= 0) return;
    jfieldID fid = env->GetStaticFieldID(cls, field_name, "J");
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }
    if (fid) env->SetStaticLongField(cls, fid, val);
}

static void spoof_java_build(JNIEnv *env) {
    jclass build_cls = env->FindClass("android/os/Build");
    if (build_cls) {
        set_static_str(env, build_cls, "MANUFACTURER", cfg.b_manufacturer);
        set_static_str(env, build_cls, "MODEL", cfg.b_model);
        set_static_str(env, build_cls, "FINGERPRINT", cfg.b_fingerprint);
        set_static_str(env, build_cls, "BRAND", cfg.b_brand);
        set_static_str(env, build_cls, "PRODUCT", cfg.b_product);
        set_static_str(env, build_cls, "DEVICE", cfg.b_device);
        set_static_str(env, build_cls, "BOARD", cfg.b_board);
        set_static_str(env, build_cls, "HARDWARE", cfg.b_hardware);
        set_static_str(env, build_cls, "ID", cfg.b_id);
        set_static_str(env, build_cls, "DISPLAY", cfg.b_display);
        set_static_str(env, build_cls, "BOOTLOADER", cfg.b_bootloader);
        set_static_str(env, build_cls, "SERIAL", cfg.b_serial);
        set_static_str(env, build_cls, "TYPE", cfg.b_type);
        set_static_str(env, build_cls, "TAGS", cfg.b_tags);
        set_static_long(env, build_cls, "TIME", cfg.b_time);
        env->DeleteLocalRef(build_cls);
    }

    jclass ver_cls = env->FindClass("android/os/Build$VERSION");
    if (ver_cls) {
        set_static_str(env, ver_cls, "RELEASE", cfg.b_release);
        set_static_str(env, ver_cls, "INCREMENTAL", cfg.b_incremental);
        set_static_str(env, ver_cls, "SECURITY_PATCH", cfg.b_security_patch);
        set_static_int(env, ver_cls, "SDK_INT", cfg.b_sdk_int);
        set_static_int(env, ver_cls, "DEVICE_INITIAL_SDK_INT", cfg.b_first_sdk);
        env->DeleteLocalRef(ver_cls);
    }
}

// --- COMPANION PARSER ---

static bool is_target_package(const char *pkg_name) {
    FILE *fp = fopen("/data/adb/modules/drm_spoofer_universal/target.prop", "r");
    if (!fp) return false;
    char line[LINE_LEN];
    bool matched = false;
    while (fgets(line, LINE_LEN, fp)) {
        if (line[0] == '#' || line[0] == '
' || line[0] == '
') continue;
        size_t len = strcspn(line, "
 ");
        line[len] = '�';
        if (len > 0 && strcmp(line, pkg_name) == 0) { matched = true; break; }
    }
    fclose(fp);
    return matched;
}

static void add_dynamic_prop(FullConfig &c, const char *k, const char *v) {
    if (c.prop_count >= MAX_PROPS) return;
    strncpy(c.props[c.prop_count].key, k, sizeof(c.props[0].key) - 1);
    c.props[c.prop_count].key[sizeof(c.props[0].key) - 1] = '�';
    strncpy(c.props[c.prop_count].val, v, sizeof(c.props[0].val) - 1);
    c.props[c.prop_count].val[sizeof(c.props[0].val) - 1] = '�';
    c.prop_count++;
}

static void companion_handler(int client) {
    FullConfig local_cfg;
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

    // 1. drm.prop
    FILE *fp = fopen("/data/adb/modules/drm_spoofer_universal/drm.prop", "r");
    if (fp) {
        char line[LINE_LEN];
        while (fgets(line, LINE_LEN, fp)) {
            if (strncmp(line, "drm_id=", 7) == 0) {
                char *val = line + 7;
                size_t len = strcspn(val, "
");
                val[len] = '�';
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

    // 2. device.prop
    fp = fopen("/data/adb/modules/drm_spoofer_universal/device.prop", "r");
    if (fp) {
        char line[LINE_LEN];
        while (fgets(line, LINE_LEN, fp)) {
            if (line[0] == '#' || line[0] == '
' || line[0] == '
') continue;
            line[strcspn(line, "
")] = '�';
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '�';
            const char *k = line;
            const char *v = eq + 1;

            if (strcmp(k, "MANUFACTURER") == 0) strncpy(local_cfg.b_manufacturer, v, sizeof(local_cfg.b_manufacturer) - 1);
            else if (strcmp(k, "MODEL") == 0) strncpy(local_cfg.b_model, v, sizeof(local_cfg.b_model) - 1);
            else if (strcmp(k, "FINGERPRINT") == 0) strncpy(local_cfg.b_fingerprint, v, sizeof(local_cfg.b_fingerprint) - 1);
            else if (strcmp(k, "BRAND") == 0) strncpy(local_cfg.b_brand, v, sizeof(local_cfg.b_brand) - 1);
            else if (strcmp(k, "PRODUCT") == 0) strncpy(local_cfg.b_product, v, sizeof(local_cfg.b_product) - 1);
            else if (strcmp(k, "DEVICE") == 0) strncpy(local_cfg.b_device, v, sizeof(local_cfg.b_device) - 1);
            else if (strcmp(k, "BOARD") == 0) strncpy(local_cfg.b_board, v, sizeof(local_cfg.b_board) - 1);
            else if (strcmp(k, "HARDWARE") == 0) strncpy(local_cfg.b_hardware, v, sizeof(local_cfg.b_hardware) - 1);
            else if (strcmp(k, "RELEASE") == 0) strncpy(local_cfg.b_release, v, sizeof(local_cfg.b_release) - 1);
            else if (strcmp(k, "ID") == 0) strncpy(local_cfg.b_id, v, sizeof(local_cfg.b_id) - 1);
            else if (strcmp(k, "DISPLAY") == 0) strncpy(local_cfg.b_display, v, sizeof(local_cfg.b_display) - 1);
            else if (strcmp(k, "INCREMENTAL") == 0) strncpy(local_cfg.b_incremental, v, sizeof(local_cfg.b_incremental) - 1);
            else if (strcmp(k, "BOOTLOADER") == 0) strncpy(local_cfg.b_bootloader, v, sizeof(local_cfg.b_bootloader) - 1);
            else if (strcmp(k, "SERIAL") == 0) strncpy(local_cfg.b_serial, v, sizeof(local_cfg.b_serial) - 1);
            else if (strcmp(k, "TYPE") == 0) strncpy(local_cfg.b_type, v, sizeof(local_cfg.b_type) - 1);
            else if (strcmp(k, "TAGS") == 0) strncpy(local_cfg.b_tags, v, sizeof(local_cfg.b_tags) - 1);
            else if (strcmp(k, "SECURITY_PATCH") == 0) strncpy(local_cfg.b_security_patch, v, sizeof(local_cfg.b_security_patch) - 1);
            else if (strcmp(k, "TIME") == 0) local_cfg.b_time = strtoll(v, nullptr, 10);
            else if (strcmp(k, "SDK_INT") == 0) local_cfg.b_sdk_int = atoi(v);
            else if (strcmp(k, "DEVICE_INITIAL_SDK_INT") == 0) local_cfg.b_first_sdk = atoi(v);
            else if (strcmp(k, "*.build.id") == 0) strncpy(local_cfg.wc_build_id, v, sizeof(local_cfg.wc_build_id) - 1);
            else if (strcmp(k, "*.security_patch") == 0) strncpy(local_cfg.wc_security_patch, v, sizeof(local_cfg.wc_security_patch) - 1);
            else if (strcmp(k, "*api_level") == 0) strncpy(local_cfg.wc_api_level, v, sizeof(local_cfg.wc_api_level) - 1);
            else if (strcmp(k, "kernel_release") == 0) strncpy(local_cfg.kernel_release, v, sizeof(local_cfg.kernel_release) - 1);
            else if (strcmp(k, "kernel_version") == 0) strncpy(local_cfg.kernel_version, v, sizeof(local_cfg.kernel_version) - 1);
            else if (strcmp(k, "cpu_hardware") == 0) strncpy(local_cfg.cpu_hardware, v, sizeof(local_cfg.cpu_hardware) - 1);
            else if (strcmp(k, "cpu_model_name") == 0) strncpy(local_cfg.cpu_model_name, v, sizeof(local_cfg.cpu_model_name) - 1);
            else if (strcmp(k, "cpu_cores") == 0) local_cfg.cpu_cores = atoi(v);
            else if (strcmp(k, "cpu_arch") == 0) strncpy(local_cfg.cpu_arch, v, sizeof(local_cfg.cpu_arch) - 1);
            else if (strcmp(k, "gpu_vendor") == 0) strncpy(local_cfg.gpu_vendor, v, sizeof(local_cfg.gpu_vendor) - 1);
            else if (strcmp(k, "gpu_renderer") == 0) strncpy(local_cfg.gpu_renderer, v, sizeof(local_cfg.gpu_renderer) - 1);
            else if (strcmp(k, "gpu_version") == 0) strncpy(local_cfg.gpu_version, v, sizeof(local_cfg.gpu_version) - 1);
            else if (strcmp(k, "ram_gb") == 0) local_cfg.ram_gb = strtoull(v, nullptr, 10);
            else if (strcmp(k, "storage_gb") == 0) local_cfg.storage_gb = strtoull(v, nullptr, 10);
            else if (strcmp(k, "screen_width") == 0) local_cfg.screen_width = atoi(v);
            else if (strcmp(k, "screen_height") == 0) local_cfg.screen_height = atoi(v);
            else if (strcmp(k, "screen_dpi") == 0) local_cfg.screen_dpi = atoi(v);
            else {
                // Qualquer outra propriedade (ro.*, gsm.*, etc.) vai para a tabela dinamica
                add_dynamic_prop(local_cfg, k, v);
            }
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
        base_pkg[pkg_len] = '�';
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

        // 1. Java Build Fields
        spoof_java_build(env);

        // 2. JNI Hook: MediaDrm
        JNINativeMethod drm_methods[] = {
            { "getPropertyByteArray", "(Ljava/lang/String;)[B", (void *)hooked_getPropertyByteArray }
        };
        api->hookJniNativeMethods(env, "android/media/MediaDrm", drm_methods, 1);
        orig_getPropertyByteArray = reinterpret_cast<jbyteArray (*)(JNIEnv *, jobject, jstring)>(drm_methods[0].fnPtr);

        // 3. JNI Hook: Build.getSerial()
        JNINativeMethod build_methods[] = {
            { "getSerial", "()Ljava/lang/String;", (void *)hooked_getSerial }
        };
        api->hookJniNativeMethods(env, "android/os/Build", build_methods, 1);
        if (env->ExceptionCheck()) env->ExceptionClear();
        orig_getSerial = reinterpret_cast<jstring (*)(JNIEnv *, jclass)>(build_methods[0].fnPtr);

        // 4. JNI Hook: DisplayMetrics
        JNINativeMethod display_methods[] = {
            { "getRealMetrics", "(Landroid/util/DisplayMetrics;)V", (void *)hooked_getRealMetrics },
            { "getMetrics", "(Landroid/util/DisplayMetrics;)V", (void *)hooked_getMetrics }
        };
        api->hookJniNativeMethods(env, "android/view/Display", display_methods, 2);
        orig_getRealMetrics = reinterpret_cast<void (*)(JNIEnv *, jobject, jobject)>(display_methods[0].fnPtr);
        orig_getMetrics = reinterpret_cast<void (*)(JNIEnv *, jobject, jobject)>(display_methods[1].fnPtr);

        // 5. PLT Hooks: Propriedades, Kernel, SELinux, CPU, RAM, Storage e GPU
        api->pltHookRegister(".*", "openat", (void *)hooked_openat, (void **)&orig_openat);
        api->pltHookRegister(".*", "fopen", (void *)hooked_fopen, (void **)&orig_fopen);
        api->pltHookRegister(".*", "uname", (void *)hooked_uname, (void **)&orig_uname);
        api->pltHookRegister(".*", "sysinfo", (void *)hooked_sysinfo, (void **)&orig_sysinfo);
        api->pltHookRegister(".*", "statfs", (void *)hooked_statfs, (void **)&orig_statfs);
        api->pltHookRegister(".*", "glGetString", (void *)hooked_glGetString, (void **)&orig_glGetString);
        api->pltHookRegister(".*", "__system_property_get", (void *)hooked_system_property_get, (void **)&orig_system_property_get);
        api->pltHookRegister(".*", "__system_property_read_callback", (void *)hooked_system_property_read_callback, (void **)&orig_system_property_read_callback);
        api->pltHookCommit();
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(DrmSpooferModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
