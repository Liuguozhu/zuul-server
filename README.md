# zuul-server
微服务之路由
zuul server demo

## 技术栈 (Technology stack)
- Spring-Boot
- Spring-Cloud
- Eureka
- Zuul

## 文档 (document)
[手把手教你搭建微服务 (spring boot +spring cloud+eureka+zuul）](https://www.zhihu.com/people/liuguozhu/activities)

## 关联项目 (correlation)
- [微服务之注册中心 (eureka-server）](https://github.com/Liuguozhu/eureka-server)
- [微服务之业务服务 (games-lobby）](https://www.zhihu.com/people/liuguozhu/activities)

## 手动打包

```bash
mvn clean assembly:assembly
```

打包完成后，会在项目根目录下的target目录里生成一个`zuul-server.tar.gz`文件，解压运行 `sh start.sh` 即可启动服务

