#################################################################################
#  Copyright (c) 2025 Contributors to the Eclipse Foundation
#
#  See the NOTICE file(s) distributed with this work for additional
#  information regarding copyright ownership.
#
#  This program and the accompanying materials are made available under the
#  terms of the Apache License, Version 2.0 which is available at
#  https://www.apache.org/licenses/LICENSE-2.0.
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
#
#  SPDX-License-Identifier: Apache-2.0
#################################################################################

FROM gradle:8.9-jdk21-alpine AS build

COPY --chown=gradle:gradle --chmod=755 api /home/gradle/src/api
COPY --chown=gradle:gradle --chmod=755 gradle /home/gradle/src/gradle
COPY --chown=gradle:gradle --chmod=755 impl /home/gradle/src/impl
COPY --chown=gradle:gradle --chmod=755 persistence/persistence-api /home/gradle/src/persistence/persistence-api
COPY --chown=gradle:gradle --chmod=755 persistence/in-memory /home/gradle/src/persistence/in-memory
COPY --chown=gradle:gradle --chmod=755 rest /home/gradle/src/rest
COPY --chown=gradle:gradle --chmod=755 runtimes/ssi-dim-wallet-stub-memory /home/gradle/src/runtimes/ssi-dim-wallet-stub-memory
COPY --chown=gradle:gradle --chmod=755 testUtils /home/gradle/src/testUtils
COPY --chown=gradle:gradle --chmod=755 utils /home/gradle/src/utils
COPY --chown=gradle:gradle --chmod=755 .dockerignore /home/gradle/src/
COPY --chown=gradle:gradle --chmod=755 build.gradle /home/gradle/src/
COPY --chown=gradle:gradle --chmod=755 gradle.properties /home/gradle/src/
COPY --chown=gradle:gradle --chmod=755 gradlew /home/gradle/src/
COPY --chown=gradle:gradle --chmod=755 gradlew.bat /home/gradle/src/
COPY --chown=gradle:gradle --chmod=755 settings.gradle /home/gradle/src/

WORKDIR /home/gradle/src

RUN gradle \
    :runtimes:ssi-dim-wallet-stub-memory:clean \
    :runtimes:ssi-dim-wallet-stub-memory:build \
    --no-daemon \
    -i \
    -x test \
    -x javadoc;

FROM eclipse-temurin:21-jre-alpine

# run as non-root user
RUN addgroup -g 11111 -S wallet && adduser -u 11111 -S -s /bin/false -G wallet wallet \
# add curl for healthcheck
&& apk --no-cache add curl

USER wallet

COPY --from=build /home/gradle/src/runtimes/ssi-dim-wallet-stub-memory/build/libs/wallet-memory-latest.jar /app/

WORKDIR /app

# Set the active Spring profile to 'prod'
ENV SPRING_PROFILES_ACTIVE=in-memory

HEALTHCHECK --start-period=30s CMD ["/bin/sh", "-c", "curl --fail http://localhost:8080/actuator/health/liveness || exit 1"]

CMD ["java", "-jar", "wallet-memory-latest.jar"]
