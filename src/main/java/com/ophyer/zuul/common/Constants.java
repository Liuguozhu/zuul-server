package com.ophyer.zuul.common;

/**
 * @author LGZ
 * @package com.ophyer.zuul
 * @className Constants
 * @description zuulserver Constants
 * @date 2019/8/6 14:21:45
 */
public interface Constants {
    //    String KEY = "Hu4fxY7fipzLOIuuCHS8rA==";//更换为自己的秘钥，可用AESUtil的generateDesKey()生成秘钥
    String KEY = "cHg5OGk0bGgxZDl6bmJhaQ==";//更换为自己的秘钥，可用AESUtil的generateDesKey()生成秘钥
    String HEADER_SERIAL = "request-serial";
    String HEADER_OFFSET = "offset";
    String HEADER_CIPHER = "cipher-text";
}
