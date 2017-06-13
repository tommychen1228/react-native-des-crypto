package tech.bigbug.reactnative.descrypto;

import android.util.Log;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;


public class DescPassUtils {
    private static final String TAG = "DescPassUtils";

    private static final String DES = "DES";
    private static final String ocKey = "6^)(9-p35@%3#4S!4S0)*0)$Y%!#O@*G$Y%%^&5(j.&^&o(pG@=+@j.&6^)(0-=+";
    public static DESKeySpec DESKeySpec = getDESKeySpecFromString(new String(ocKey.getBytes()));


    //从字符串生成DES Key
    public static DESKeySpec getDESKeySpecFromString(String strKey) {
        DESKeySpec spec = null;
        try {
            spec = new DESKeySpec(strKey.getBytes());
        } catch (InvalidKeyException ex) {
            Log.e(TAG, "Get des key spec  fault", ex);
        }
        return spec;
    }

//    //取得DES Key对应的字符串,此为传给Objective C的密码字串
//    public static String getDESKeyString() {
//        return byte2hex(DESKeySpec.getKey());
//    }

    /**
     * 加密 数组
     *
     * @param src 明文(字节)
     * @return 密文(字节)
     * @throws Exception
     */

    public static byte[] encrypt(byte[] src) throws Exception {
        // DES算法要求有一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        // 创建一个密匙工厂，然后用它把DESKeySpec转换成
        // 一个SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(DESKeySpec);

        // Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(DES);

        // 用密匙初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);

        // 现在，获取数据并加密
        // 正式执行加密操作
        return cipher.doFinal(src);
    }

    /**
     * 解密 数组
     *
     * @param src 密文(字节)
     *            密钥，长度必须是8的倍数
     * @return 明文(字节)
     * @throws Exception
     */
    public static byte[] decrypt(byte[] src) throws Exception {
        // DES算法要求有一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        // 创建一个密匙工厂，然后用它把DESKeySpec转换成
        // 一个SecresrctKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(DESKeySpec);

        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance(DES);

        // 用密匙初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, sr);

        // 现在，获取数据并解密
        // 正式执行解密操作
        return cipher.doFinal(src);
    }

    /**
     * 加密字符串
     *
     * @param src 明文(字符串)
     * @return 密文(16进制字符串)
     * @throws Exception
     */
    public final static String encrypt(String src) {
        try {
            return byte2hex(encrypt(src.getBytes()));
        } catch (Exception ex) {
            Log.e(TAG, "encrypt fault", ex);
        }
        return null;
    }

    /**
     * 解密 字符串
     *
     * @param src 密文(字符串)
     * @return 明文(字符串)
     * @throws Exception
     */
    public final static String decrypt(String src) {
        try {
            return new String(decrypt(hex2byte(src.getBytes())));
        } catch (Exception e) {
            Log.e(TAG, "Decrypt fault", e);
        }
        return null;
    }

    //字节到十六进制串转换
    public static String byte2hex(byte[] b) {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = Integer.toHexString(b[n] & 0xFF);
            if (stmp.length() == 1)
                hs += ("0" + stmp);
            else
                hs += stmp;
        }
        return hs.toUpperCase();
    }

    //十六进制串到字节转换
    public static byte[] hex2byte(byte[] b) {
        if ((b.length % 2) != 0)
            throw new IllegalArgumentException("长度不是偶数!");

        byte[] b2 = new byte[b.length / 2];

        for (int n = 0; n < b.length; n += 2) {
            String item = new String(b, n, 2);
            b2[n / 2] = (byte) Integer.parseInt(item, 16);
        }
        return b2;
    }
}