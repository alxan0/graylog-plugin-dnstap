#!/usr/bin/env bash
# Minimal PKI for dnstap over TLS, if you have no internal CA. Run it in an empty directory:
#   make-dnstap-pki.sh GRAYLOG_HOSTNAME [RELAY_NAME]
# Creates:
#   ca.crt / ca.key           the CA (keep ca.key offline: neither server needs it)
#   server.crt / server.key   for the Graylog Dnstap input (SAN = GRAYLOG_HOSTNAME, serverAuth, PKCS#8 key)
#   client.crt / client.key   for the socat relay on the DNS server (clientAuth)
set -euo pipefail
GL=${1:?usage: $0 GRAYLOG_HOSTNAME [RELAY_NAME]}
RELAY=${2:-$(hostname -s)-dnstap}
[ -e ca.key ] && { echo "ca.key exists here: use an empty directory" >&2; exit 1; }
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=dnstap CA" -keyout ca.key -out ca.crt 2>/dev/null
mk() { # NAME CN SAN EKU
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$2" -keyout "$1.rsa.key" -out "$1.csr" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' "$3" "$4" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in "$1.rsa.key" -out "$1.key"   # Graylog wants PKCS#8 PEM
  rm -f "$1.rsa.key" "$1.csr" "$1.ext"
}
if [[ $GL =~ ^[0-9.]+$ ]]; then san="IP:$GL"; else san="DNS:$GL"; fi
mk server "$GL" "$san" serverAuth
mk client "$RELAY" "DNS:$RELAY" clientAuth
chmod 644 ca.crt server.crt client.crt
echo "Graylog input:   server.crt  server.key  ca.crt (trusted client certs)"
echo "DNS server relay: client.crt  client.key  ca.crt"
echo "Keep ca.key offline."
