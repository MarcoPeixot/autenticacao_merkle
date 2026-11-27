# Ambiente Linux para compilar e rodar o código do patch (patch-v5/) e o verificador em C.
# Traz o compilador, o OpenSSL e o que os testes do verificador usam (make, pkg-config e Python);
# os fontes entram por volume na hora de rodar.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev libssl-dev linux-libc-dev openssl \
    make pkg-config python3 \
 && rm -rf /var/lib/apt/lists/*
