package tech.bigbug.reactnative.descrypto;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;


public class RCTDesCrypto extends ReactContextBaseJavaModule {
    private final static String DES = "DES";

    public RCTDesCrypto(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "RCTDesCrypto";
    }

    @ReactMethod
    public void encrypt(String data, String key, Callback success, Callback error) {

        String result = DescPassUtils.encrypt(data);

        success.invoke(result);
    }

    @ReactMethod
    public void decrypt(String data, String key, Callback success, Callback error) {
        String result = DescPassUtils.decrypt(data);

        success.invoke(result);
    }

}
