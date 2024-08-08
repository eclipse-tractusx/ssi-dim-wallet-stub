FROM gradle:8.9-jdk21-alpine AS build

COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src

RUN gradle clean build --no-daemon -i -x test -x javadoc;

FROM eclipse-temurin:21-jre-alpine

# run as non-root user
RUN addgroup -g 11111 -S wallet && adduser -u 11111 -S -s /bin/false -G wallet wallet

# add curl for healthcheck
RUN apk --no-cache add curl

USER wallet

COPY --from=build /home/gradle/src/build/libs/wallet-latest.jar /app/

WORKDIR /app

HEALTHCHECK --start-period=30s CMD curl --fail http://localhost:8080/actuator/health/liveness || exit 1

CMD ["java", "-jar", "wallet-latest.jar"]
