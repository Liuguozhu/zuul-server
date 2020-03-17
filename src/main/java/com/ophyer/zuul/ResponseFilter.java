package com.ophyer.zuul;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.ophyer.zuul.common.*;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

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
        return false;
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext context = getCurrentContext();
        InputStream stream = context.getResponseDataStream();
        HttpServletRequest request = context.getRequest();
        HttpServletResponse response = context.getResponse();
        String actionName = request.getRequestURI();
        String clientIp = IpUtil.getIpAddr(request);
        logger.info("response|{}|{}", clientIp, actionName);
        String offset = StringUtil.randomString(16);
        offset = Base64.encode(offset.getBytes(StandardCharsets.UTF_8));//偏移量用base64编码
        String serial = RequestFilter.getHeaderParam(request, Constants.HEADER_SERIAL);//请求id，长度为32位
        String cipherText = MD5Util.getMD5String(serial + Constants.KEY + offset);
        response.addHeader(Constants.HEADER_OFFSET, offset);
        response.addHeader(Constants.HEADER_SERIAL, serial);
        response.addHeader(Constants.HEADER_CIPHER, cipherText);
        // FIXME 特别注意 同域请求无需加，跨域请求需要加上下面这行，允许客户端从跨域请求的响应头中获取这些信息,如果想要所有都允许，换成* ，否则客户端获取响应头部信息时会报错 Refused to get unsafe header “xxx”
        response.addHeader("Access-Control-Expose-Headers", Constants.HEADER_OFFSET + "," + Constants.HEADER_SERIAL + "," + Constants.HEADER_CIPHER);
        response.addHeader("Access-Control-Max-Age", "3600");
        String body;
        try {
            body = StreamUtils.copyToString(stream, Charset.forName("UTF-8"));
        } catch (IOException e) {
            logger.error("Response body 获取错误：{}", e.getMessage());
            e.printStackTrace();
            context.setSendZuulResponse(false);
            context.setResponseStatusCode(500);
            context.setResponseBody("{\"code\":500,\"result\":\"" + e.getMessage() + "\"}");
            return null;
        }
        logger.info("响应body={}", body);

        if (StringUtils.isNotBlank(body)) {
            try {
                body = AESUtil.encrypt(body, Constants.KEY, offset);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                context.setSendZuulResponse(false);
                context.setResponseStatusCode(500);
                context.setResponseBody("{\"code\":500,\"result\":\"返回结果加密错误！\"}");
            }
        }
        context.setResponseBody(body);

        return null;
    }
}
