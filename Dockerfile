#################################################################################
#  Copyright (c) 2024 Contributors to the Eclipse Foundation
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
