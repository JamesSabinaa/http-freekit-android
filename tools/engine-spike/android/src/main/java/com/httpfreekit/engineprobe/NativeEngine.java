package com.httpfreekit.engineprobe;

/** Research-only registration target for the unchanged, pinned upstream JNI. */
public final class NativeEngine {
    static { System.loadLibrary("hev-socks5-tunnel"); }

    public native boolean TProxyStartService(String configurationPath, int descriptor);
    public native boolean TProxyStopService();
    public native boolean TProxyIsRunning();
    public native long[] TProxyGetStats();
}
