#!/bin/bash
# update_haproxy_certs.sh
# Chạy với sudo
# Lệnh: ./update_haproxy_certs.sh [reload|start|stop]

ACTION=$1

CERTS_SRC="/opt/haproxy_manager/certs"
CERTS_DST="/etc/haproxy/certs"
CRT_LIST="/opt/haproxy_manager/crt-list.txt"
DOMAINS_FILE="/opt/haproxy_manager/domains.map"
BACKENDS_FILE="/opt/haproxy_manager/backends.json"
SECURITY_FILE="/opt/haproxy_manager/security.json"
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"

function copy_certs() {
    mkdir -p "$CERTS_DST"
    chmod 700 "$CERTS_DST"
    cp -f "$CERTS_SRC"/*.pem "$CERTS_DST"/
    chmod 600 "$CERTS_DST"/*.pem
    ls "$CERTS_DST"/*.pem > "$CRT_LIST"
}

function load_security() {
    if [ -f "$SECURITY_FILE" ]; then
        PROTOCOLS=$(jq -r '.protocols' "$SECURITY_FILE")
        CIPHERS=$(jq -r '.ciphers' "$SECURITY_FILE")
        HSTS=$(jq -r '.hsts' "$SECURITY_FILE")
        RATE_LIMIT=$(jq -r '.rate_limit' "$SECURITY_FILE")
        XSS=$(jq -r '.xss_protect' "$SECURITY_FILE")
    else
        PROTOCOLS="TLSv1.2+TLSv1.3"
        CIPHERS="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
        HSTS=true
        RATE_LIMIT=100
        XSS=true
    fi
}

function generate_config() {
    cat > "$HAPROXY_CFG" <<EOF
global
    log /dev/log local0
    maxconn 2000
    tune.ssl.default-dh-param 2048
    ssl-default-bind-ciphers $CIPHERS
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11
    ssl-default-bind-protocols $PROTOCOLS

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5s
    timeout client  50s
    timeout server  50s
    option forwardfor

frontend https_front
    bind *:443 ssl crt-list $CRT_LIST
    mode http
    option http-server-close
EOF

    if [ "$HSTS" == "true" ]; then
        echo "    http-response set-header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"" >> "$HAPROXY_CFG"
    fi
    if [ "$XSS" == "true" ]; then
        echo "    http-response set-header X-Content-Type-Options nosniff" >> "$HAPROXY_CFG"
        echo "    http-response set-header X-XSS-Protection 1; mode=block" >> "$HAPROXY_CFG"
    fi

    echo "    default_backend web_back" >> "$HAPROXY_CFG"

    cat >> "$HAPROXY_CFG" <<EOF

backend web_back
    mode http
    balance roundrobin
EOF

    if [ -f "$BACKENDS_FILE" ]; then
        jq -c '.[]' "$BACKENDS_FILE" | while read b; do
            NAME=$(echo $b | jq -r '.name')
            IP=$(echo $b | jq -r '.ip')
            PORT=$(echo $b | jq -r '.port')
            SSL=$(echo $b | jq -r '.ssl')
            if [ "$SSL" == "true" ]; then
                echo "    server $NAME $IP:$PORT ssl check" >> "$HAPROXY_CFG"
            else
                echo "    server $NAME $IP:$PORT check" >> "$HAPROXY_CFG"
            fi
        done
    fi
}

function haproxy_action() {
    case "$ACTION" in
        reload)
            systemctl reload haproxy
            echo "HAProxy reloaded."
            ;;
        start)
            systemctl start haproxy
            echo "HAProxy started."
            ;;
        stop)
            systemctl stop haproxy
            echo "HAProxy stopped."
            ;;
        *)
            echo "Usage: $0 [reload|start|stop]"
            exit 1
            ;;
    esac
}

# --- Main ---
copy_certs
load_security
generate_config
haproxy_action
