# syntax=docker/dockerfile:1

# --- Build the server jar -------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-26 AS build
WORKDIR /src
COPY pom.xml .
COPY core core
# The parent POM lists every module; the agent only needs its POM to be present.
COPY agent/pom.xml agent/pom.xml
COPY server server
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -q -pl server -am -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true package

# sqlite-jdbc normally unpacks its native library into /tmp at startup, but /tmp is mounted
# noexec in the container. Extract it now so it can be loaded from a read-only location.
RUN mkdir /native /tmp/boot && cd /tmp/boot \
 && jar xf /src/server/target/netledger-server.jar BOOT-INF/lib \
 && arch="$(uname -m | sed 's/arm64/aarch64/')" \
 && jar xf BOOT-INF/lib/sqlite-jdbc-*.jar "org/sqlite/native/Linux/$arch/libsqlitejdbc.so" \
 && cp "org/sqlite/native/Linux/$arch/libsqlitejdbc.so" /native/

# Offline copy of the IEEE MAC registry; the server refreshes it monthly into /data.
RUN mkdir /oui \
 && for f in oui/oui.csv oui28/mam.csv oui36/oui36.csv; do \
      curl -fsSL -A "NetLedger (self-hosted network inventory)" -o "/oui/${f##*/}" "https://standards-oui.ieee.org/$f"; \
    done

# --- Runtime --------------------------------------------------------------------------------
FROM eclipse-temurin:21-jre
RUN groupadd --system netledger \
 && useradd --system --gid netledger --no-create-home --shell /usr/sbin/nologin netledger \
 && mkdir /data && chown netledger:netledger /data
WORKDIR /app
COPY --from=build /src/server/target/netledger-server.jar app.jar
COPY --from=build /oui oui
COPY --from=build /native native
ENV NETLEDGER_DATA_DIR=/data \
    NETLEDGER_OUI_DIR=/app/oui \
    NETLEDGER_OUI_UPDATE=true \
    NETLEDGER_BIND_ADDRESS=0.0.0.0
VOLUME /data
USER netledger
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", \
            "-Dorg.sqlite.lib.path=/app/native", "-Dorg.sqlite.lib.name=libsqlitejdbc.so", \
            "-jar", "/app/app.jar"]
