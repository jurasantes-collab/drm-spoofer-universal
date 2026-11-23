#!/system/bin/sh
MODDIR=${0%/*}

while [ "$(getprop sys.boot_completed)" != "1" ]; do
  sleep 1
done

REAL_MODEL=$(getprop ro.product.model)
REAL_DEVICE=$(getprop ro.product.device)
REAL_PRODUCT=$(getprop ro.product.name)
REAL_BOARD=$(getprop ro.product.board)
REAL_PLATFORM=$(getprop ro.board.platform)
REAL_PATCH=$(getprop ro.build.version.security_patch)
REAL_INC=$(getprop ro.build.version.incremental)

# 1. Mascara /proc/cpuinfo dinamicamente
cp /proc/cpuinfo "$MODDIR/fake_cpuinfo"
[ -n "$REAL_BOARD" ] && sed -i "s/$REAL_BOARD/crownqlte/gI" "$MODDIR/fake_cpuinfo"
[ -n "$REAL_PLATFORM" ] && sed -i "s/$REAL_PLATFORM/crownqlte/gI" "$MODDIR/fake_cpuinfo"
chmod 444 "$MODDIR/fake_cpuinfo"
mount --bind "$MODDIR/fake_cpuinfo" /proc/cpuinfo

# 1.5 Mascara /proc/version
echo "Linux version 4.9.118-17432506 (dpi@SWDD5905) (gcc version 4.9.x 20150123 (prerelease) (GCC) ) #1 SMP PREEMPT Thu Dec 12 18:10:22 KST 2019" > "$MODDIR/fake_version"
chmod 444 "$MODDIR/fake_version"
mount --bind "$MODDIR/fake_version" /proc/version

# 2. Mascara /vendor/build.prop dinamicamente
if [ -f /vendor/build.prop ]; then
  mkdir -p "$MODDIR/vendor"
  cp /vendor/build.prop "$MODDIR/vendor/build.prop"
  [ -n "$REAL_MODEL" ] && sed -i "s/$REAL_MODEL/SM-N9600/gI" "$MODDIR/vendor/build.prop"
  [ -n "$REAL_PRODUCT" ] && sed -i "s/$REAL_PRODUCT/crownqlteub/gI" "$MODDIR/vendor/build.prop"
  [ -n "$REAL_DEVICE" ] && sed -i "s/$REAL_DEVICE/crownqlte/gI" "$MODDIR/vendor/build.prop"
  [ -n "$REAL_INC" ] && sed -i "s/$REAL_INC/N9600ZHS4CSL2/gI" "$MODDIR/vendor/build.prop"
  [ -n "$REAL_BOARD" ] && sed -i "s/$REAL_BOARD/crownqlte/gI" "$MODDIR/vendor/build.prop"
  [ -n "$REAL_PLATFORM" ] && sed -i "s/$REAL_PLATFORM/crownqlte/gI" "$MODDIR/vendor/build.prop"
  [ -n "$REAL_PATCH" ] && sed -i "s/$REAL_PATCH/2019-12-01/g" "$MODDIR/vendor/build.prop"
  sed -i "s/test-keys/release-keys/gI" "$MODDIR/vendor/build.prop"
  sed -i "s/userdebug/user/gI" "$MODDIR/vendor/build.prop"
  chmod 444 "$MODDIR/vendor/build.prop"
  mount --bind "$MODDIR/vendor/build.prop" /vendor/build.prop
fi

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

# 4. Coloca SELinux em Enforcing
setenforce 1
