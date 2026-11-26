# Ambiente Linux para compilar e rodar o código do patch (patch-v5/).
# Só traz o compilador e o OpenSSL; os fontes entram por volume na hora de rodar.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev libssl-dev linux-libc-dev openssl \
 && rm -rf /var/lib/apt/lists/*
