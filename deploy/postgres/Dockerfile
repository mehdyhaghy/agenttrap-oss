# Postgres 18 with Apache AGE (Apache-2.0), a graph extension queried with
# openCypher. It links sources through the keys, agent IDs, TLS stacks and
# networks they share; see internal/hub/graph.go.
FROM postgres:18-alpine AS build
ARG AGE_VERSION=1.8.0
ARG AGE_SHA512=8103dc6a4daec0441c2bdfe4e456be619d04526efa5c4e1a5148a29d7e6359e5df7d9a1fabbc6a6a08f6229c4d6f8634b7bf3554eca8ffb58550382542279866
RUN apk add --no-cache build-base bison flex perl curl
WORKDIR /src
RUN curl -fsSLo age.tar.gz "https://dlcdn.apache.org/age/PG18/${AGE_VERSION}/apache-age-${AGE_VERSION}-src.tar.gz" \
 && echo "${AGE_SHA512}  age.tar.gz" | sha512sum -c - \
 && tar -xzf age.tar.gz --strip-components=1 \
 && make with_llvm=no -j"$(nproc)" \
 && make with_llvm=no install DESTDIR=/out

FROM postgres:18-alpine
COPY --from=build /out/usr/local/ /usr/local/
CMD ["postgres", "-c", "shared_preload_libraries=age"]
