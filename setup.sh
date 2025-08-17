#!/bin/bash
# setup.sh - Tự động cài đặt HAProxy Manager Dashboard từ GitHub

set -e

REPO_URL="https://github.com/duynghiaqn/haproxy-ui.git"
PROJECT_DIR="/opt/haproxy_manager"

echo "=== Cập nhật hệ thống ==="
sudo apt update && sudo apt upgrade -y

echo "=== Cài đặt HAProxy, Certbot, Python, git ==="
sudo apt install -y haproxy certbot python3 python3-pip python3-venv git

echo "=== Clone HAProxy UI từ GitHub ==="
sudo rm -rf "$PROJECT_DIR"
sudo git clone "$REPO_URL" "$PROJECT_DIR"

echo "=== Tạo thư mục certs và file cần thiết ==="
sudo mkdir -p "$PROJECT_DIR/certs"
sudo touch "$PROJECT_DIR/domains.map" "$PROJECT_DIR/crt-list.txt"
sudo chmod -R 700 "$PROJECT_DIR/certs"

echo "=== Tạo virtualenv và cài Flask ==="
python3 -m venv "$PROJECT_DIR/venv"
source "$PROJECT_DIR/venv/bin/activate"
pip install --upgrade pip
pip install flask

echo "=== Cấu hình quyền sudo cho www-data chạy script update_haproxy_certs.sh ==="
SUDO_LINE="www-data ALL=(ALL) NOPASSWD: $PROJECT_DIR/update_haproxy_certs.sh"
if ! sudo grep -qF "$SUDO_LINE" /etc/sudoers; then
    echo "$SUDO_LINE" | sudo EDITOR='tee -a' visudo
fi

echo "=== Tạo systemd service ==="
SERVICE_FILE="/etc/systemd/system/haproxy_manager.service"
sudo tee "$SERVICE_FILE" > /dev/null <<EOL
[Unit]
Description=HAProxy Manager Flask App
After=network.target

[Service]
User=www-data
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/venv/bin/python3 $PROJECT_DIR/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOL

echo "=== Reload systemd & enable service ==="
sudo systemctl daemon-reload
sudo systemctl enable haproxy_manager
sudo systemctl start haproxy_manager

echo "=== Tạo thư mục HAProxy certs ==="
sudo mkdir -p /etc/haproxy/certs
sudo chmod 700 /etc/haproxy/certs

echo "=== Setup hoàn tất! ==="
echo "Truy cập Dashboard: http://<server_ip>:5000"
echo "Login: admin / admin"
