#!/system/bin/sh
MODID=drm_spoofer_universal
LIVE_PATH="/data/adb/modules/$MODID"

ui_print "- Instalando Universal Runtime Spoofer..."

if [ -d "$LIVE_PATH/config" ] && [ "$(ls -A "$LIVE_PATH/config")" ]; then
    ui_print "- Atualizando com a configuracao existente..."
fi

[ -f "$MODPATH/service.sh" ] && set_perm "$MODPATH/service.sh" 0 0 0755
[ -d "$MODPATH/config" ] && set_perm_recursive "$MODPATH/config" 0 0 0755 0644

ui_print "- Instalacao concluida!"
