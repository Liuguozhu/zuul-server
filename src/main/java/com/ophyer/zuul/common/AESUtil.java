package com.ophyer.zuul.common;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Security;

/**
 * @author LGZ
 * @package com.ophyer.zuul
 * @className AESUtil
 * @description zuulserver AESUtil
 * @date 2019/8/6 11:50:22
 */
public class AESUtil {
    private static final Logger logger = LoggerFactory.getLogger(AESUtil.class);

    /**
     * AES加解密
     */
    private static final String ALGORITHM = "AES";
    /**
     * 工作模式：CBC
     */
    private static final String TRANSFORM_CBC_PKCS7 = "AES/CBC/PKCS7Padding";
//    private static final String TRANSFORM_CBC_PKCS5 = "AES/CBC/PKCS5Padding";//加密解密的方法1只支持5.用7报错
    /**
     * 供应商
     */
    private static final String PROVIDER = "BC";

    /**
     * 解密
     *
     * @param encryptedData 加密字符串
     * @param key           秘钥
     * @param offset        偏移量
     * @return 解密后字符串
     */
    public static String decrypt(String encryptedData, String key, String offset) throws GeneralSecurityException, UnsupportedEncodingException {
        //被加密的数据
        byte[] dataByte = Base64.decode(encryptedData);
        //加密秘钥
        byte[] keyByte = Base64.decode(key);
        //偏移量
        byte[] ivByte = Base64.decode(offset);

        //方法一
//            Cipher e = Cipher.getInstance(TRANSFORM_CBC_PKCS5);
//            SecretKeySpec spec = new SecretKeySpec(keyByte, ALGORITHM);
//            IvParameterSpec iv = new IvParameterSpec(ivByte);//使用CBC模式，需要一个向量iv，可增加加密算法的强度
//            e.init(Cipher.DECRYPT_MODE, spec, iv);
//            byte[] resultByte = e.doFinal(dataByte);

        //方法二
        Security.addProvider(new BouncyCastleProvider());
        Cipher e = Cipher.getInstance(TRANSFORM_CBC_PKCS7, PROVIDER);
        SecretKeySpec spec = new SecretKeySpec(keyByte, ALGORITHM);
        AlgorithmParameters parameters = AlgorithmParameters.getInstance(ALGORITHM);
        parameters.init(new IvParameterSpec(ivByte));
        e.init(Cipher.DECRYPT_MODE, spec, parameters);// 初始化
        byte[] resultByte = e.doFinal(dataByte);
        if (null != resultByte && resultByte.length > 0) {
            return new String(resultByte, StandardCharsets.UTF_8.displayName());
        }
        return "";
    }

    /**
     * 加密
     *
     * @param originalData 原文-等待加密的字符串
     * @param key          加密秘钥
     * @param offset       偏移量
     * @return 加密后字符串
     */
    public static String encrypt(String originalData, String key, String offset) throws GeneralSecurityException {
        //等待加密的数据
        byte[] dataByte = originalData.getBytes();
        //加密秘钥
        byte[] keyByte = Base64.decode(key);
        //偏移量
        byte[] ivByte = Base64.decode(offset);
        //方法一
//            Cipher e = Cipher.getInstance(TRANSFORM_CBC_PKCS5);
//            SecretKeySpec spec = new SecretKeySpec(keyByte, ALGORITHM);
//            IvParameterSpec iv = new IvParameterSpec(ivByte);//使用CBC模式，需要一个向量iv，可增加加密算法的强度
//            e.init(Cipher.ENCRYPT_MODE, spec, iv);
//            byte[] resultByte = e.doFinal(dataByte);

        //方法二
        Security.addProvider(new BouncyCastleProvider());
        Cipher e = Cipher.getInstance(TRANSFORM_CBC_PKCS7, PROVIDER);
        SecretKeySpec spec = new SecretKeySpec(keyByte, ALGORITHM);
        AlgorithmParameters parameters = AlgorithmParameters.getInstance(ALGORITHM);
        parameters.init(new IvParameterSpec(ivByte));
        e.init(Cipher.ENCRYPT_MODE, spec, parameters);// 初始化
        byte[] resultByte = e.doFinal(dataByte);
        if (null != resultByte && resultByte.length > 0) {
            return Base64.encode(resultByte);
        }
        return null;
    }

    /**
     * 秘钥生成工具
     *
     * @param length 建议为128/192/256
     * @return
     * @throws Exception
     */
    public static byte[] generateDesKey(int length) throws Exception {
        //实例化
        KeyGenerator kgen;
        kgen = KeyGenerator.getInstance("AES");
        //设置密钥长度
        kgen.init(length);
        //生成密钥
        SecretKey secretKey = kgen.generateKey();

        //获取密钥的二进制编码
        return secretKey.getEncoded();//Base64.encode(keyByte);//用base64编码秘钥
    }

    public static void main(String[] args) throws Exception {
        byte[] keyByte = generateDesKey(128);
        String key = Base64.encode(keyByte);
        logger.info("key base64={}", key);
//        String key = StringUtil.randomString(16);
//        logger.info("key={}", key);
//        String keyEncode = Base64.encode(key.getBytes());
//        logger.info("keyEncode={}", keyEncode);

        String originalData = "{\"a\":100,\"b\":\"str\"}";

        String iv = "ymzrgrk6wr0s2fwr";
        iv = Base64.encode(iv.getBytes(StandardCharsets.UTF_8));
        logger.info("data:{}", originalData);
        logger.info("offset:{}", iv);

        logger.info("offset decode:{}", Base64.decode(iv));
        String encryptedData = AESUtil.encrypt(originalData, key, iv);
        logger.info(encryptedData);
        String body = AESUtil.decrypt(encryptedData, key, iv);
        logger.info(body);

        String a = "gdT9s/M9RaOP+vciKbaS/A==";
        String r = URLEncoder.encode(a, "utf-8");
        logger.info(r);
    }
}
