#!/system/bin/sh
MODDIR=${0%/*}

while [ "$(getprop sys.boot_completed)" != "1" ]; do
  sleep 1
done

clean_prop() {
  getprop "$1" | tr -d '\r\n'
}

REAL_MODEL=$(clean_prop ro.product.model)
REAL_DEVICE=$(clean_prop ro.product.device)
REAL_PRODUCT=$(clean_prop ro.product.name)
REAL_BOARD=$(clean_prop ro.product.board)
REAL_PLATFORM=$(clean_prop ro.board.platform)
REAL_PATCH=$(clean_prop ro.build.version.security_patch)
REAL_INC=$(clean_prop ro.build.version.incremental)

# 1. Mascara /proc/cpuinfo dinamicamente
if [ -r /proc/cpuinfo ]; then
  cp /proc/cpuinfo "$MODDIR/fake_cpuinfo"
  tr -d '\r' < "$MODDIR/fake_cpuinfo" > "$MODDIR/fake_cpuinfo.tmp" && mv "$MODDIR/fake_cpuinfo.tmp" "$MODDIR/fake_cpuinfo"
  [ -n "$REAL_BOARD" ] && sed -i "s/$REAL_BOARD/crownqlte/gI" "$MODDIR/fake_cpuinfo"
  [ -n "$REAL_PLATFORM" ] && sed -i "s/$REAL_PLATFORM/crownqlte/gI" "$MODDIR/fake_cpuinfo"
  chmod 0444 "$MODDIR/fake_cpuinfo"
  mount --bind "$MODDIR/fake_cpuinfo" /proc/cpuinfo 2>/dev/null || true
fi

# 1.5 Mascara /proc/version
printf '%s\n' "Linux version 4.9.118-17432506 (dpi@SWDD5905) (gcc version 4.9.x 20150123 (prerelease) (GCC) ) #1 SMP PREEMPT Thu Dec 12 18:10:22 KST 2019" > "$MODDIR/fake_version"
chmod 0444 "$MODDIR/fake_version"
mount --bind "$MODDIR/fake_version" /proc/version 2>/dev/null || true

# 2. Mascara build.prop (/vendor/build.prop e/ou /system/build.prop)
patch_build_prop() {
  SRC_PROP="$1"
  DST_PROP="$2"
  [ -f "$SRC_PROP" ] || return 0

  mkdir -p "$(dirname "$DST_PROP")"
  cp "$SRC_PROP" "$DST_PROP"
  tr -d '\r' < "$DST_PROP" > "$DST_PROP.tmp" && mv "$DST_PROP.tmp" "$DST_PROP"

  [ -n "$REAL_MODEL" ] && sed -i "s/$REAL_MODEL/SM-N9600/gI" "$DST_PROP"
  [ -n "$REAL_PRODUCT" ] && sed -i "s/$REAL_PRODUCT/crownqlteub/gI" "$DST_PROP"
  [ -n "$REAL_DEVICE" ] && sed -i "s/$REAL_DEVICE/crownqlte/gI" "$DST_PROP"
  [ -n "$REAL_INC" ] && sed -i "s/$REAL_INC/N9600ZHS4CSL2/gI" "$DST_PROP"
  [ -n "$REAL_BOARD" ] && sed -i "s/$REAL_BOARD/crownqlte/gI" "$DST_PROP"
  [ -n "$REAL_PLATFORM" ] && sed -i "s/$REAL_PLATFORM/crownqlte/gI" "$DST_PROP"
  [ -n "$REAL_PATCH" ] && sed -i "s/$REAL_PATCH/2019-12-01/g" "$DST_PROP"
  sed -i "s/test-keys/release-keys/gI" "$DST_PROP"
  sed -i "s/userdebug/user/gI" "$DST_PROP"

  chmod 0644 "$DST_PROP"
  mount --bind "$DST_PROP" "$SRC_PROP" 2>/dev/null || true
}

patch_build_prop "/vendor/build.prop" "$MODDIR/vendor/build.prop"
patch_build_prop "/system/build.prop" "$MODDIR/system/build.prop"

# 3. Mascara bootloader e estado de boot
resetprop -n ro.boot.verifiedbootstate green
resetprop -n ro.boot.flash.locked 1
resetprop -n ro.boot.vbmeta.device_state locked
resetprop -n ro.boot.warranty_bit 0
resetprop -n ro.warranty_bit 0
resetprop -n ro.serialno R58K914728N
resetprop -n ro.boot.serialno R58K914728N
resetprop -n ro.bootloader N9600ZHS4CSL2
resetprop -n ro.boot.bootloader N9600ZHS4CSL2

# 4. Coloca SELinux em Enforcing (evita falhas se o kernel bloquear)
setenforce 1 2>/dev/null || true
