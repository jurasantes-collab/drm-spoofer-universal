package com.syscore.spoofer;

import android.os.Build;
import android.util.Log;
import java.lang.reflect.Field;

public class SpoofEntry {
    private static final String TAG = "SysCore";

    public static void apply(String[] keys, String[] values) {
        if (keys == null || values == null || keys.length != values.length) return;

        for (int i = 0; i < keys.length; i++) {
            String k = keys[i];
            String v = values[i];
            if (k == null || v == null || v.isEmpty()) continue;

            if (!setStaticField(Build.class, k, v)) {
                setStaticField(Build.VERSION.class, k, v);
            }
        }
        Log.d(TAG, "SpoofEntry.apply concluido (" + keys.length + " chaves)");
    }

    private static boolean setStaticField(Class<?> clazz, String fieldName, String value) {
        try {
            Field f = clazz.getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(null, value);
            Log.d(TAG, "DEX Build." + fieldName + " = " + value);
            return true;
        } catch (NoSuchFieldException ignored) {
            return false;
        } catch (Throwable t) {
            Log.e(TAG, "Erro ao alterar " + fieldName + ": " + t.getMessage());
            return false;
        }
    }
}
