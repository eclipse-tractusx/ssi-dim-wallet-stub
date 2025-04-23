#################################################################################
#  Copyright (c) 2025 Contributors to the Eclipse Foundation
#  Copyright (c) 2025 LKS Next
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

COPY api /home/gradle/src/api
COPY gradle /home/gradle/src/gradle
COPY impl /home/gradle/src/impl
COPY persistence/persistence-api /home/gradle/src/persistence/persistence-api
COPY persistence/in-memory /home/gradle/src/persistence/in-memory
COPY rest /home/gradle/src/rest
COPY runtimes/ssi-dim-wallet-stub-memory /home/gradle/src/runtimes/ssi-dim-wallet-stub-memory
COPY testUtils /home/gradle/src/testUtils
COPY .dockerignore /home/gradle/src/
COPY build.gradle /home/gradle/src/
COPY gradle.properties /home/gradle/src/
COPY gradlew /home/gradle/src/
COPY gradlew.bat /home/gradle/src/
COPY settings.gradle /home/gradle/src/

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

HEALTHCHECK --start-period=30s CMD ["/bin/sh", "-c", "curl --fail http://localhost:8080/actuator/health/liveness || exit 1"]

CMD ["java", "-jar", "wallet-memory-latest.jar"]
