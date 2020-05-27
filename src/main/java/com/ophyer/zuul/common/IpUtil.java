package com.ophyer.zuul.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

public class IpUtil {
    private static Logger logger = LoggerFactory.getLogger(IpUtil.class);

    public IpUtil() {
    }

    public static String getIpAddr(HttpServletRequest request) {
        String ip = request.getHeader("x-forwarded-for");//格式为X-Forwarded-For:client1,proxy1,proxy2，一般情况下，第一个ip为客户端真实ip，后面的为经过的代理服务器ip。现在大部分的代理都会加上这个请求头。
        logger.info("x-forwarded-for:[{}]", ip);
        //Proxy-Client-IP/WL- Proxy-Client-IP 一般是经过apache http服务器的请求才会有，用apache http做代理时一般会加上Proxy-Client-IP请求头，而WL-Proxy-Client-IP是他的weblogic插件加上的头。
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
            logger.info("Proxy-Client-IP:[{}]", ip);
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
            logger.info("WL-Proxy-Client-IP:[{}]", ip);
        }

        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_CLIENT_IP");//有些代理服务器会加上此请求头。
            logger.info("HTTP_CLIENT_IP:[{}]", ip);
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");//nginx代理一般会加上此请求头。
            logger.info("X-Real-IP:[{}]", ip);
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
            logger.info("RemoteAddr:[{}]", ip);
        }
        String realIp = request.getHeader("X-Real-IP");
        if (!ip.equals(realIp)) {
            logger.info("X-Real-IP:[{}]", realIp);
            ip = "";
        }
        /**
         * 这些请求头都不是http协议里的标准请求头，也就是说这个是各个代理服务器自己规定的表示客户端地址的请求头。如果哪天有一个代理服务器软件用oooo-client-ip这个请求头代表客户端请求，那上面的代码就不行了。
         *
         * 这些请求头不是代理服务器一定会带上的，网络上的很多匿名代理就没有这些请求头，所以获取到的客户端ip不一定是真实的客户端ip。代理服务器一般都可以自定义请求头设置。
         *
         * 即使请求经过的代理都会按自己的规范附上代理请求头，上面的代码也不能确保获得的一定是客户端ip。不同的网络架构，判断请求头的顺序是不一样的。
         *
         * 最重要的一点，请求头都是可以伪造的。如果一些对客户端校验较严格的应用（比如投票）要获取客户端ip，应该直接使用ip=request.getRemoteAddr()，虽然获取到的可能是代理的ip而不是客户端的ip，但这个获取到的ip基本上是不可能伪造的，也就杜绝了刷票的可能。(有分析说arp欺骗+syn有可能伪造此ip，如果真的可以，这是所有基于TCP协议都存在的漏洞)，这个ip是tcp连接里的ip。
         */

        return ip;
    }
}
