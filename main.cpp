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
constexpr int MAX_PROPS = 160;

struct PropEntry {
    char key[96];
    char val[256];
    bool is_prefix;
};

struct HardwareConfig {
    bool active = false;
    jbyte drm_id[ID_LEN];

    uint64_t ram_gb = 6;
    uint64_t storage_gb = 128;

    char cpu_hardware[128] = "Qualcomm Technologies, Inc SDM845";
    char cpu_model_name[128] = "ARMv8 Processor rev 12 (v8l)";
    int cpu_cores = 8;
    char cpu_arch[32] = "aarch64";
    char cpu_max_freq[32] = "2803200";
    char cpu_min_freq[32] = "300000";
    char soc_id[32] = "321";

    char gpu_vendor[64] = "Qualcomm";
    char gpu_renderer[128] = "Adreno (TM) 630";
    char gpu_version[128] = "OpenGL ES 3.2 V@0415.0";
    char gpu_model_sysfs[64] = "Adreno630v2";

    int screen_width = 1440;
    int screen_height = 2960;
    int screen_dpi = 560;

    char kernel_release[128] = "4.9.112-17257921";
    char kernel_version[256] = "#1 SMP PREEMPT Thu Dec 19 15:30:10 KST 2019";
    char full_proc_version[384] = "Linux version 4.9.112-17257921 (dpi@SWDH8411) (gcc version 4.9.x 20150123 (prerelease) (GCC)) #1 SMP PREEMPT Thu Dec 19 15:30:10 KST 2019";

    char build_manufacturer[64] = "samsung";
    char build_model[64] = "SM-N9600";
    char build_brand[64] = "samsung";
    char build_product[64] = "crownqlteub";
    char build_device[64] = "crownqlte";
    char build_board[64] = "sdm845";
    char build_hardware[64] = "qcom";
    char build_fingerprint[256] = "samsung/crownqlteub/crownqlte:9/PPR1.180610.011/N9600ZHS4CSL2:user/release-keys";
    char build_id[64] = "PPR1.180610.011";
    char build_display[96] = "PPR1.180610.011.N9600ZHS4CSL2";
    char build_incremental[64] = "N9600ZHS4CSL2";
    char build_bootloader[64] = "N9600ZHS4CSL2";
    char build_serial[64] = "R58K914728N";
    char build_type[32] = "user";
    char build_tags[32] = "release-keys";
    char build_release[32] = "9";
    char build_security_patch[32] = "2019-12-01";
    int build_sdk_int = 28;
    int64_t build_time = 1576769410000LL;

    int prop_count = 0;
    PropEntry props[MAX_PROPS];
};

static HardwareConfig cfg;

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

static const char* lookup_spoof_prop(const char *name) {
    if (!name) return nullptr;

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

    size_t nlen = strlen(name);
    for (int i = 0; i < cfg.prop_count; i++) {
        if (!cfg.props[i].is_prefix) {
            if (strcmp(name, cfg.props[i].key) == 0) {
                return cfg.props[i].val;
            }
        } else {
            size_t klen = strlen(cfg.props[i].key);
            if (nlen >= klen && strcmp(name + (nlen - klen), cfg.props[i].key) == 0) {
                return cfg.props[i].val;
            }
        }
    }
    return nullptr;
}

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

static int create_memfd_text(const char *tag, const char *text) {
    int fd = static_cast<int>(syscall(__NR_memfd_create, tag, 0));
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
            "processor\t: %d\n"
            "model name\t: %s\n"
            "BogoMIPS\t: 38.40\n"
            "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
            "CPU implementer\t: 0x41\n"
            "CPU architecture: 8\n"
            "CPU variant\t: 0x1\n"
            "CPU part\t: 0xd80\n"
            "CPU revision\t: 12\n\n",
            i, cfg.cpu_model_name);
        write(fd, buf, len);
    }
    int tail_len = snprintf(buf, sizeof(buf), "Hardware\t: %s\n", cfg.cpu_hardware);
    write(fd, buf, tail_len);
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static int create_fake_meminfo_fd() {
    uint64_t total_kb = cfg.ram_gb * 1024ULL * 1024ULL;
    uint64_t free_kb = total_kb / 3;
    uint64_t avail_kb = (total_kb * 2) / 3;

    char buf[512];
    snprintf(buf, sizeof(buf),
        "MemTotal:       %llu kB\n"
        "MemFree:        %llu kB\n"
        "MemAvailable:   %llu kB\n"
        "Buffers:          131072 kB\n"
        "Cached:          1572864 kB\n"
        "SwapTotal:       2097152 kB\n"
        "SwapFree:        2097152 kB\n",
        static_cast<unsigned long long>(total_kb),
        static_cast<unsigned long long>(free_kb),
        static_cast<unsigned long long>(avail_kb));
    return create_memfd_text("meminfo", buf);
}

static int intercept_virtual_path(const char *pathname) {
    if (!pathname) return -1;

    if (strcmp(pathname, "/proc/cpuinfo") == 0) {
        return create_fake_cpuinfo_fd();
    }
    if (strcmp(pathname, "/proc/meminfo") == 0 && cfg.ram_gb > 0) {
        return create_fake_meminfo_fd();
    }
    if (strcmp(pathname, "/proc/version") == 0 && strlen(cfg.full_proc_version) > 0) {
        char buf[420];
        snprintf(buf, sizeof(buf), "%s\n", cfg.full_proc_version);
        return create_memfd_text("version", buf);
    }
    if (strcmp(pathname, "/sys/fs/selinux/enforce") == 0) {
        return create_memfd_text("enforce", "1");
    }
    if (strcmp(pathname, "/sys/devices/soc0/machine") == 0 && strlen(cfg.build_board) > 0) {
        char buf[80];
        snprintf(buf, sizeof(buf), "%s\n", cfg.build_board);
        return create_memfd_text("machine", buf);
    }
    if (strcmp(pathname, "/sys/devices/soc0/soc_id") == 0 && strlen(cfg.soc_id) > 0) {
        char buf[48];
        snprintf(buf, sizeof(buf), "%s\n", cfg.soc_id);
        return create_memfd_text("soc_id", buf);
    }
    if (strcmp(pathname, "/sys/class/kgsl/kgsl-3d0/gpu_model") == 0 && strlen(cfg.gpu_model_sysfs) > 0) {
        char buf[80];
        snprintf(buf, sizeof(buf), "%s\n", cfg.gpu_model_sysfs);
        return create_memfd_text("gpu_model", buf);
    }
    if (strncmp(pathname, "/sys/devices/system/cpu/cpu", 27) == 0) {
        if (strstr(pathname, "cpuinfo_max_freq") && strlen(cfg.cpu_max_freq) > 0) {
            char buf[48];
            snprintf(buf, sizeof(buf), "%s\n", cfg.cpu_max_freq);
            return create_memfd_text("max_freq", buf);
        }
        if (strstr(pathname, "cpuinfo_min_freq") && strlen(cfg.cpu_min_freq) > 0) {
            char buf[48];
            snprintf(buf, sizeof(buf), "%s\n", cfg.cpu_min_freq);
            return create_memfd_text("min_freq", buf);
        }
    }
    return -1;
}

static int hooked_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    int vfd = intercept_virtual_path(pathname);
    if (vfd >= 0) return vfd;

    return orig_openat ? orig_openat(dirfd, pathname, flags, mode) : -1;
}

static FILE* hooked_fopen(const char *pathname, const char *mode) {
    if (pathname && mode && strchr(mode, 'r')) {
        int vfd = intercept_virtual_path(pathname);
        if (vfd >= 0) return fdopen(vfd, mode);
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
        if (strlen(cfg.cpu_arch) > 0) {
            strncpy(buf->machine, cfg.cpu_arch, sizeof(buf->machine) - 1);
            buf->machine[sizeof(buf->machine) - 1] = '\0';
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

static int hooked_system_property_get(const char *name, char *value) {
    const char *spoof = lookup_spoof_prop(name);
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
    const char *spoof = lookup_spoof_prop(name);
    if (wrap && wrap->orig_cb) {
        wrap->orig_cb(wrap->orig_cookie, name, spoof != nullptr ? spoof : value, serial);
    }
}

static void hooked_system_property_read_callback(
    const prop_info *pi,
    void (*callback)(void *cookie, const char *name, const char *value, uint32_t serial),
    void *cookie) {
    if (orig_system_property_read_callback) {
        CallbackWrapper wrap{callback, cookie};
        orig_system_property_read_callback(pi, custom_prop_callback, &wrap);
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

static jstring hooked_getSerial(JNIEnv *env, jclass clazz) {
    if (strlen(cfg.build_serial) > 0) {
        return env->NewStringUTF(cfg.build_serial);
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

static void set_static_string_field(JNIEnv *env, jclass cls, const char *field_name, const char *val) {
    if (!cls || !val || strlen(val) == 0) return;
    jfieldID fid = env->GetStaticFieldID(cls, field_name, "Ljava/lang/String;");
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }
    if (fid) {
        jstring jval = env->NewStringUTF(val);
        env->SetStaticObjectField(cls, fid, jval);
        env->DeleteLocalRef(jval);
    }
}

static void apply_java_build_fields(JNIEnv *env) {
    jclass buildCls = env->FindClass("android/os/Build");
    if (buildCls) {
        set_static_string_field(env, buildCls, "MANUFACTURER", cfg.build_manufacturer);
        set_static_string_field(env, buildCls, "MODEL", cfg.build_model);
        set_static_string_field(env, buildCls, "BRAND", cfg.build_brand);
        set_static_string_field(env, buildCls, "PRODUCT", cfg.build_product);
        set_static_string_field(env, buildCls, "DEVICE", cfg.build_device);
        set_static_string_field(env, buildCls, "BOARD", cfg.build_board);
        set_static_string_field(env, buildCls, "HARDWARE", cfg.build_hardware);
        set_static_string_field(env, buildCls, "FINGERPRINT", cfg.build_fingerprint);
        set_static_string_field(env, buildCls, "ID", cfg.build_id);
        set_static_string_field(env, buildCls, "DISPLAY", cfg.build_display);
        set_static_string_field(env, buildCls, "BOOTLOADER", cfg.build_bootloader);
        set_static_string_field(env, buildCls, "SERIAL", cfg.build_serial);
        set_static_string_field(env, buildCls, "TYPE", cfg.build_type);
        set_static_string_field(env, buildCls, "TAGS", cfg.build_tags);

        if (cfg.build_time > 0) {
            jfieldID timeFid = env->GetStaticFieldID(buildCls, "TIME", "J");
            if (env->ExceptionCheck()) env->ExceptionClear();
            else if (timeFid) env->SetStaticLongField(buildCls, timeFid, cfg.build_time);
        }
        env->DeleteLocalRef(buildCls);
    }

    jclass verCls = env->FindClass("android/os/Build$VERSION");
    if (verCls) {
        set_static_string_field(env, verCls, "RELEASE", cfg.build_release);
        set_static_string_field(env, verCls, "INCREMENTAL", cfg.build_incremental);
        set_static_string_field(env, verCls, "SECURITY_PATCH", cfg.build_security_patch);

        if (cfg.build_sdk_int > 0) {
            jfieldID sdkFid = env->GetStaticFieldID(verCls, "SDK_INT", "I");
            if (env->ExceptionCheck()) env->ExceptionClear();
            else if (sdkFid) env->SetStaticIntField(verCls, sdkFid, cfg.build_sdk_int);
        }
        env->DeleteLocalRef(verCls);
    }
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

static void add_prop_entry(HardwareConfig &c, const char *key, const char *val) {
    if (c.prop_count >= MAX_PROPS) return;
    bool prefix = false;
    if (key[0] == '*') {
        prefix = true;
        key++;
    }
    for (int i = 0; i < c.prop_count; i++) {
        if (c.props[i].is_prefix == prefix && strcmp(c.props[i].key, key) == 0) {
            strncpy(c.props[i].val, val, sizeof(c.props[i].val) - 1);
            c.props[i].val[sizeof(c.props[i].val) - 1] = '\0';
            return;
        }
    }
    PropEntry &e = c.props[c.prop_count++];
    e.is_prefix = prefix;
    strncpy(e.key, key, sizeof(e.key) - 1);
    e.key[sizeof(e.key) - 1] = '\0';
    strncpy(e.val, val, sizeof(e.val) - 1);
    e.val[sizeof(e.val) - 1] = '\0';
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
        while (fgets(line, LINE_LEN, fp)) {
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            char *key = line;
            char *val = eq + 1;
            val[strcspn(val, "\r\n")] = '\0';

            if (strcmp(key, "MANUFACTURER") == 0) strncpy(local_cfg.build_manufacturer, val, sizeof(local_cfg.build_manufacturer) - 1);
            else if (strcmp(key, "MODEL") == 0) strncpy(local_cfg.build_model, val, sizeof(local_cfg.build_model) - 1);
            else if (strcmp(key, "BRAND") == 0) strncpy(local_cfg.build_brand, val, sizeof(local_cfg.build_brand) - 1);
            else if (strcmp(key, "PRODUCT") == 0) strncpy(local_cfg.build_product, val, sizeof(local_cfg.build_product) - 1);
            else if (strcmp(key, "DEVICE") == 0) strncpy(local_cfg.build_device, val, sizeof(local_cfg.build_device) - 1);
            else if (strcmp(key, "BOARD") == 0) strncpy(local_cfg.build_board, val, sizeof(local_cfg.build_board) - 1);
            else if (strcmp(key, "HARDWARE") == 0) strncpy(local_cfg.build_hardware, val, sizeof(local_cfg.build_hardware) - 1);
            else if (strcmp(key, "FINGERPRINT") == 0) strncpy(local_cfg.build_fingerprint, val, sizeof(local_cfg.build_fingerprint) - 1);
            else if (strcmp(key, "ID") == 0) strncpy(local_cfg.build_id, val, sizeof(local_cfg.build_id) - 1);
            else if (strcmp(key, "DISPLAY") == 0) strncpy(local_cfg.build_display, val, sizeof(local_cfg.build_display) - 1);
            else if (strcmp(key, "INCREMENTAL") == 0) strncpy(local_cfg.build_incremental, val, sizeof(local_cfg.build_incremental) - 1);
            else if (strcmp(key, "BOOTLOADER") == 0) strncpy(local_cfg.build_bootloader, val, sizeof(local_cfg.build_bootloader) - 1);
            else if (strcmp(key, "SERIAL") == 0) strncpy(local_cfg.build_serial, val, sizeof(local_cfg.build_serial) - 1);
            else if (strcmp(key, "TYPE") == 0) strncpy(local_cfg.build_type, val, sizeof(local_cfg.build_type) - 1);
            else if (strcmp(key, "TAGS") == 0) strncpy(local_cfg.build_tags, val, sizeof(local_cfg.build_tags) - 1);
            else if (strcmp(key, "RELEASE") == 0) strncpy(local_cfg.build_release, val, sizeof(local_cfg.build_release) - 1);
            else if (strcmp(key, "SECURITY_PATCH") == 0) strncpy(local_cfg.build_security_patch, val, sizeof(local_cfg.build_security_patch) - 1);
            else if (strcmp(key, "SDK_INT") == 0) local_cfg.build_sdk_int = atoi(val);
            else if (strcmp(key, "TIME") == 0) local_cfg.build_time = strtoll(val, nullptr, 10);
            else if (strcmp(key, "ram_gb") == 0) local_cfg.ram_gb = strtoull(val, nullptr, 10);
            else if (strcmp(key, "storage_gb") == 0) local_cfg.storage_gb = strtoull(val, nullptr, 10);
            else if (strcmp(key, "cpu_hardware") == 0) strncpy(local_cfg.cpu_hardware, val, sizeof(local_cfg.cpu_hardware) - 1);
            else if (strcmp(key, "cpu_model_name") == 0) strncpy(local_cfg.cpu_model_name, val, sizeof(local_cfg.cpu_model_name) - 1);
            else if (strcmp(key, "cpu_cores") == 0) local_cfg.cpu_cores = atoi(val);
            else if (strcmp(key, "cpu_arch") == 0) strncpy(local_cfg.cpu_arch, val, sizeof(local_cfg.cpu_arch) - 1);
            else if (strcmp(key, "cpu_max_freq") == 0) strncpy(local_cfg.cpu_max_freq, val, sizeof(local_cfg.cpu_max_freq) - 1);
            else if (strcmp(key, "cpu_min_freq") == 0) strncpy(local_cfg.cpu_min_freq, val, sizeof(local_cfg.cpu_min_freq) - 1);
            else if (strcmp(key, "soc_id") == 0) strncpy(local_cfg.soc_id, val, sizeof(local_cfg.soc_id) - 1);
            else if (strcmp(key, "gpu_vendor") == 0) strncpy(local_cfg.gpu_vendor, val, sizeof(local_cfg.gpu_vendor) - 1);
            else if (strcmp(key, "gpu_renderer") == 0) strncpy(local_cfg.gpu_renderer, val, sizeof(local_cfg.gpu_renderer) - 1);
            else if (strcmp(key, "gpu_version") == 0) strncpy(local_cfg.gpu_version, val, sizeof(local_cfg.gpu_version) - 1);
            else if (strcmp(key, "gpu_model_sysfs") == 0) strncpy(local_cfg.gpu_model_sysfs, val, sizeof(local_cfg.gpu_model_sysfs) - 1);
            else if (strcmp(key, "screen_width") == 0) local_cfg.screen_width = atoi(val);
            else if (strcmp(key, "screen_height") == 0) local_cfg.screen_height = atoi(val);
            else if (strcmp(key, "screen_dpi") == 0) local_cfg.screen_dpi = atoi(val);
            else if (strcmp(key, "kernel_release") == 0) strncpy(local_cfg.kernel_release, val, sizeof(local_cfg.kernel_release) - 1);
            else if (strcmp(key, "kernel_version") == 0) strncpy(local_cfg.kernel_version, val, sizeof(local_cfg.kernel_version) - 1);
            else if (strcmp(key, "full_proc_version") == 0) strncpy(local_cfg.full_proc_version, val, sizeof(local_cfg.full_proc_version) - 1);
            else if (strchr(key, '.') != nullptr) {
                add_prop_entry(local_cfg, key, val);
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

        apply_java_build_fields(env);

        JNINativeMethod drm_methods[] = {
            { "getPropertyByteArray", "(Ljava/lang/String;)[B", (void *)hooked_getPropertyByteArray }
        };
        api->hookJniNativeMethods(env, "android/media/MediaDrm", drm_methods, 1);
        orig_getPropertyByteArray = reinterpret_cast<jbyteArray (*)(JNIEnv *, jobject, jstring)>(drm_methods[0].fnPtr);

        JNINativeMethod serial_methods[] = {
            { "getSerial", "()Ljava/lang/String;", (void *)hooked_getSerial }
        };
        api->hookJniNativeMethods(env, "android/os/Build", serial_methods, 1);
        orig_getSerial = reinterpret_cast<jstring (*)(JNIEnv *, jclass)>(serial_methods[0].fnPtr);

        JNINativeMethod display_methods[] = {
            { "getRealMetrics", "(Landroid/util/DisplayMetrics;)V", (void *)hooked_getRealMetrics },
            { "getMetrics", "(Landroid/util/DisplayMetrics;)V", (void *)hooked_getMetrics }
        };
        api->hookJniNativeMethods(env, "android/view/Display", display_methods, 2);
        orig_getRealMetrics = reinterpret_cast<void (*)(JNIEnv *, jobject, jobject)>(display_methods[0].fnPtr);
        orig_getMetrics = reinterpret_cast<void (*)(JNIEnv *, jobject, jobject)>(display_methods[1].fnPtr);

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
