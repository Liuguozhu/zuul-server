package com.ophyer.zuul;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

/**
 * @author LGZ
 * @package PACKAGE_NAME
 * @className com.ophyer.ZuulServerApplication
 * @description eurekaserver com.ophyer.ZuulServerApplication
 * @date 2019/7/3 14:40:57
 */
@SpringBootApplication
@EnableZuulProxy
@EnableDiscoveryClient
public class ZuulServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(ZuulServerApplication.class, args);
    }
}

