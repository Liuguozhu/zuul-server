package com.ophyer.zuul;

import com.google.gson.Gson;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.netflix.zuul.http.HttpServletRequestWrapper;
import com.netflix.zuul.http.ServletInputStreamWrapper;
import com.ophyer.zuul.common.*;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.*;

/**
 * @author LGZ
 * @package com.ophyer.zuul
 * @className RequestFilter
 * @description zuulserver RequestFilter
 * @date 2019/8/5 17:35:57
 */
@Component
public class RequestFilter extends ZuulFilter {

    private static Logger logger = LoggerFactory.getLogger(RequestFilter.class);

    @Value("${zuul.filter}")
    private String filter;

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
        return FilterConstants.PRE_TYPE;
    }

    /**
     * filterOrder：过滤的顺序
     *
     * @return
     */
    @Override
    public int filterOrder() {
        return 0;
    }

    /**
     * shouldFilter：这里可以写逻辑判断，是否要过滤，本文true,永远过滤,过滤，就会走run方法，不过滤，则跳过run方法
     *
     * @return
     */
    @Override
    public boolean shouldFilter() {
        if (Objects.isNull(filter) || "".equals(filter))
            return false;

        return Boolean.valueOf(filter);
    }

    @Override
    public Object run() throws ZuulException {
        // 获取到request
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        HttpServletResponse response = ctx.getResponse();
        // 请求方法
        String method = request.getMethod();
        String actionName = request.getRequestURI();
        String clientIp = IpUtil.getIpAddr(request);
        logger.info("request|{}|{}", clientIp, actionName);
        if (clientIp == null || "".equals(clientIp)) {
            logger.info("获取不到请求IP，拒绝转发！");
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(HttpStatus.SC_FORBIDDEN);
            ctx.setResponseBody("{\"code\":403,\"result\":\"access denied!\"}");
            return null;
        }
        String clientIpArray[] = clientIp.split(",");
        if (clientIpArray.length != 1) {
            logger.info("多个请求IP，拒绝转发！");
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(HttpStatus.SC_FORBIDDEN);
            ctx.setResponseBody("{\"code\":403,\"result\":\"access denied!\"}");
            return null;
        }

        String agent = request.getHeader("User-Agent");
        logger.info("请求来源:{}", agent);
        if (agent.indexOf("micromessenger") <= 0 && agent.indexOf("MicroMessenger") <= 0) {//是否来自微信
            logger.info("请求不是来自微信，拒绝转发！");
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(HttpStatus.SC_FORBIDDEN);
            ctx.setResponseBody("{\"code\":403,\"result\":\"access denied!\"}");
            return null;
        }


        //判断是否是预检请求
        if ("OPTIONS".equals(request.getMethod())) {//这里通过判断请求的方法，判断此次是否是预检请求，如果是，立即返回一个204状态吗，标示，允许跨域；预检后，正式请求，这个方法参数就是我们设置的post了
            logger.info("预检请求***");
            ctx.setSendZuulResponse(true);
            return null;
        }

        // 验证请求头
        boolean verifyHeader = verifyHeader(request);
        if (!verifyHeader) {
            logger.info("请求头部错误，拒绝转发！");
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(HttpStatus.SC_FORBIDDEN);
            ctx.setResponseBody("{\"code\":403,\"result\":\"access denied!\"}");
            return null;
        }
        logger.info("验证通过，解析后转发");

        String offset = getHeaderParam(request, Constants.HEADER_OFFSET);//解密body用的偏移量，长度为16位字符串
        logger.info("请求方式={}", method);
        // get方法和post、put方法处理方式不同
        if ("GET".equals(method)) {
            executeGet(ctx, request, offset);
        } else if ("POST".equals(method) || "PUT".equals(method) || "DELETE".equals(method)) {
            // 获取请求的输入流
            InputStream in;
            try {
                in = request.getInputStream();
            } catch (IOException e) {
                logger.error("解析请求流错误：{}", e.getMessage());
                ctx.setSendZuulResponse(false);
                ctx.setResponseStatusCode(500);
                ctx.setResponseBody("{\"code\":500,\"result\":\"" + e.getMessage() + "\"}");
                return null;//请求不合法
            }
            String body;
            try {
                body = StreamUtils.copyToString(in, Charset.forName("UTF-8"));
            } catch (IOException e) {
                logger.error("请求流转字符串错误：{}", e.getMessage());
                ctx.setSendZuulResponse(false);
                ctx.setResponseStatusCode(500);
                ctx.setResponseBody("{\"code\":500,\"result\":\"" + e.getMessage() + "\"}");
                return null;//请求不合法
            }
            // 如果body为空初始化为空json
//            if (StringUtils.isBlank(body)) {
//                body = "{}";
//            }
            logger.info("请求body={}", body);

            try {
                executePost(ctx, request, body, offset);
            } catch (GeneralSecurityException | UnsupportedEncodingException | IllegalArgumentException e) {
                e.printStackTrace();
                logger.error("POST body 解密错误：{}", e.getMessage());
                ctx.setSendZuulResponse(false);
                ctx.setResponseStatusCode(500);
                ctx.setResponseBody("{\"code\":500,\"result\":\"" + e.getMessage() + "\"}");
                return null;//请求不合法
            }
        }
        return null;//请求合法
    }

    // 验证请求头，false，验证不通过；true验证通过
    // 签名规则：md5(serial+秘钥+偏移量)
    private boolean verifyHeader(HttpServletRequest request) {
        String serial = getHeaderParam(request, Constants.HEADER_SERIAL);//每次请求都随机生成一个序列号作为请求id，长度为32位
        String offset = getHeaderParam(request, Constants.HEADER_OFFSET);//解密body用的偏移量，长度为16位字符串
        String cipherText = getHeaderParam(request, Constants.HEADER_CIPHER);//头签名
        logger.info(Constants.HEADER_SERIAL + ":{}", serial);
        logger.info(Constants.HEADER_OFFSET + ":{}", offset);
        logger.info(Constants.HEADER_CIPHER + ":{}", cipherText);
        if (StringUtils.isEmpty(serial) || StringUtils.isEmpty(cipherText) || StringUtils.isEmpty(offset))
            return false;
        // 验证签名
        String sign = MD5Util.getMD5String(serial + Constants.KEY + offset);
        logger.info("请求签名{}", cipherText);
        logger.info("生成签名{}", sign);
        return cipherText.equals(sign);
    }

    static String getHeaderParam(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        if (StringUtils.isEmpty(value)) {
            logger.info("header里没获取到{}，从参数中获取.", name);
            value = request.getParameter(name);
        }
        return value;
    }


    private void executeGet(RequestContext ctx, HttpServletRequest request, String offset) {
        // 关键步骤，一定要get一下,下面才能取到值requestQueryParams
        request.getParameterMap();
        Map<String, List<String>> requestQueryParams = ctx.getRequestQueryParams();
        if (requestQueryParams == null) {
            requestQueryParams = new HashMap<>();
        }
        Map<String, List<String>> finalRequestQueryParams = requestQueryParams;
        requestQueryParams.forEach((k, v) -> {
            logger.info("解码前 k ：{}", k);
            logger.info("解码前 v ：{}", v);
            List<String> arrayList = new ArrayList<>();
            v.forEach(s -> {
                logger.info("解码前 s ：{}", s);
                String aes_decodedStr;
                try {
                    aes_decodedStr = AESUtil.decrypt(s, Constants.KEY, offset);
                } catch (GeneralSecurityException | UnsupportedEncodingException e) {
                    e.printStackTrace();
                    logger.error("GET 请求解密错误：{}", e.getMessage());
                    ctx.setSendZuulResponse(false);
                    ctx.setResponseStatusCode(500);
                    ctx.setResponseBody("{\"code\":500,\"result\":\"" + e.getMessage() + "\"}");
                    return;
                }
                arrayList.add(aes_decodedStr);
            });
            finalRequestQueryParams.put(k, arrayList);
        });
        ctx.setRequestQueryParams(requestQueryParams);

        Gson gson = new Gson();
        String body = gson.toJson(requestQueryParams);
        logger.info("解密后请求参数{}", body);
    }

    private void executePost(RequestContext ctx, HttpServletRequest request, String body, String offset) throws GeneralSecurityException, UnsupportedEncodingException {
        if (StringUtils.isBlank(body)) {
            return;
        }
        String newBody = AESUtil.decrypt(body, Constants.KEY, offset);
        logger.info("解密后请求参数{}", newBody);
        final byte[] reqBodyBytes = newBody.getBytes();

        // 重写上下文的HttpServletRequestWrapper
        ctx.setRequest(new HttpServletRequestWrapper(request) {
            @Override
            public ServletInputStream getInputStream() throws IOException {
                return new ServletInputStreamWrapper(reqBodyBytes);
            }

            @Override
            public int getContentLength() {
                return reqBodyBytes.length;
            }

            @Override
            public long getContentLengthLong() {
                return reqBodyBytes.length;
            }
        });
    }
}
