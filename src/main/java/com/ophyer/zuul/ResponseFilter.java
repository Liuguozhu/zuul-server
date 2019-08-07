package com.ophyer.zuul;

import com.google.gson.Gson;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.ophyer.zuul.common.AESUtil;
import com.ophyer.zuul.common.Constants;
import com.ophyer.zuul.common.MD5Util;
import com.ophyer.zuul.common.StringUtil;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static com.netflix.zuul.context.RequestContext.getCurrentContext;

/**
 * @author LGZ
 * @package com.ophyer.zuul
 * @className ResponseFilter
 * @description zuulserver ResponseFilter
 * @date 2019/8/6 9:52:46
 */
@Component
public class ResponseFilter extends ZuulFilter {

    private static Logger logger = LoggerFactory.getLogger(ResponseFilter.class);

    /**
     * pre：路由之前
     * routing：路由之时
     * post： 路由之后
     * error：发送错误调用
     *
     * @return
     */
    @Override
    public String filterType() {
        return FilterConstants.POST_TYPE;
    }

    /**
     * filterOrder：过滤的顺序
     *
     * @return
     */
    @Override
    public int filterOrder() {
        return FilterConstants.SEND_RESPONSE_FILTER_ORDER - 2;
    }

    /**
     * shouldFilter：这里可以写逻辑判断，是否要过滤，本文true,永远过滤, 过滤，就会进入run
     *
     * @return
     */
    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext context = getCurrentContext();
        InputStream stream = context.getResponseDataStream();
        HttpServletRequest request = context.getRequest();
        HttpServletResponse response = context.getResponse();
        String offset = StringUtil.randomString(16);
        offset = Base64.encode(offset.getBytes(StandardCharsets.UTF_8));//偏移量用base64编码
        logger.info("随机偏移量={}", offset);
        String serial = request.getHeader(Constants.HEADER_SERIAL);//请求id，长度为32位
        String cipherText = MD5Util.getMD5String(serial + Constants.KEY + offset);
        response.addHeader(Constants.HEADER_OFFSET, offset);
        response.addHeader(Constants.HEADER_SERIAL, serial);
        response.addHeader(Constants.HEADER_CIPHER, cipherText);
        String body = null;
        try {
            body = StreamUtils.copyToString(stream, Charset.forName("UTF-8"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        logger.info("响应body={}", body);

        if (StringUtils.isNotBlank(body)) {
            Gson gson = new Gson();
            @SuppressWarnings("unchecked")
            Map<String, String> result = gson.fromJson(body, Map.class);
            logger.info("响应resultMap={}", result);
            body = gson.toJson(result);
            body = AESUtil.encrypt(body, Constants.KEY, offset);

        }
        context.setResponseBody(body);

        return null;
    }
}
