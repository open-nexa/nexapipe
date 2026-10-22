# ProGuard/R8 rules for the release build.
#
# The release build is minified and shrunk, so these are the rules that keep it
# working. Each one is here because something breaks without it, and the
# reason is written down next to it.

# ---------------------------------------------------------------------
# The JNI bridge.
#
# The Rust side exports its entry points as
# `Java_com_nexa_pipe_IrohProxy_nativeSomething` and the runtime looks each
# symbol up by the class name and the method name. R8 renames both by
# default, and every native call in the app would then fail with an
# UnsatisfiedLinkError — so the class keeps its name and so do its native
# methods.
#
# `-keep class … { native <methods>; }` keeps the class and every method
# declared `native` in it, which is the whole surface the Rust side binds.
# The object holds no logic of its own, so there is nothing here worth
# shrinking.
-keep class com.nexa.pipe.IrohProxy {
    native <methods>;
}

# The library is loaded by name, and the class that loads it is the one
# above; nothing else here loads native code.
-keepclasseswithmembernames class * {
    native <methods>;
}

# ---------------------------------------------------------------------
# The debug logs.
#
# `Log.d` and `Log.v` are the app's own noise, and a release build has no
# business shipping it: the on-screen log panel and logcat both carry it, and
# a debug build — which is the one a developer runs against a real account —
# is where a header dump or a frame preview ends up in someone else's log.
#
# `Log.w` and `Log.e` stay: they are the ones that say something went wrong.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}

# ---------------------------------------------------------------------
# The line numbers, without the file names.
#
# A crash report that names a source file is a map of the app for whoever
# reads it. The line numbers are what makes the report useful, and they are
# kept without the names.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
