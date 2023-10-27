# 使用基础镜像
# FROM adoptopenjdk:17-jdk-hotspot
FROM openjdk:17

# JAVA_OPS参数可以通过k8s命令行传入覆盖
ENV JAVA_OPTS="-Xms128m -Xmx128m"
ENV LANG=zh_CN.UTF-8
# 设置上海时区，否则日志输出的时间是UTC时间
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
# 设置工作目录
WORKDIR /app
# 暴露端口号
# EXPOSE 8080

# 复制应用程序 JAR 文件到容器中
COPY target/oauth21-0.0.1-SNAPSHOT.jar /app/your-app.jar

# 设置容器启动命令
CMD ["java", "-jar", "/app/your-app.jar"]

# 或者
# ENTRYPOINT exec java -Xmx${JVM_XMS} -Xms${JVM_XMS} -Djava.security.egd=file:/dev/./urandom -jar -Dspring.profiles.active=${SPRING_PROFILES_ACTIVE} /app.jar
