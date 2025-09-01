package uz.csec.captcha;

public class NativeLib {
    static {
        System.loadLibrary("captcha");
    }
    public native String getCaptcha(android.content.res.AssetManager assetManager);
    public native String verifyCaptcha(String captchaId, int x, int y, float scaleX, float scaleY);
}
