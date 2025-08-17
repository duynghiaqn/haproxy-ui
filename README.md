# HAProxy Manager Dashboard

Quản lý HAProxy multi-domain SSL/Wildcard thông qua **Flask UI**, tích hợp upload PEM, Certbot tự động gia hạn, reload HAProxy tự động, và dashboard SSL.

---

## 1. Tính năng

- Login admin (`admin / admin`)  
- Dashboard tổng quan domain & SSL  
- Thêm / Xóa domain  
- Upload PEM → tự động copy vào `/etc/haproxy/certs` + reload HAProxy  
- Renew SSL từng domain → Certbot → copy PEM → reload HAProxy  
- Auto SSL renew 12h background  
- Highlight SSL **Expired (đỏ)** / **Gần hết hạn <30 ngày (vàng)**  
- SweetAlert2 confirm popup cho delete / renew  
- Reload HAProxy manual  
- Bảo mật route admin, PEM chmod 600, thư mục 700  

---

## 2. Yêu cầu

- Ubuntu / Debian  
- Python3 + pip  
- HAProxy >= 2.4  
- Certbot  
- `sudo` cho user `www-data` không cần password cho script update HAProxy  

---

## 3. Cài đặt tự động

Chỉ cần chạy file `setup.sh` (xem chi tiết bên dưới). Script sẽ:

- Cài HAProxy, Certbot, Python3, pip, Flask  
- Clone ứng dụng từ GitHub: `https://github.com/duynghiaqn/haproxy-ui`  
- Tạo virtualenv, cài dependencies  
- Tạo thư mục `/etc/haproxy/certs` và set quyền  
- Tạo systemd service để chạy Flask app nền  
- Cấu hình sudo cho user `www-data` chạy script update HAProxy  

Sau khi chạy xong, truy cập dashboard tại: `http://<server_ip>:5000`  
Login: `admin / admin`  

---

## 4. Sử dụng Dashboard

- **Thêm Domain:** Nhập domain → Add  
- **Upload PEM:** Chọn domain → Upload file PEM  
- **Xóa Domain:** Click Delete → Confirm  
- **Renew SSL:** Click Renew SSL → Confirm → Certbot tự động tạo PEM  
- **Reload HAProxy:** Click Reload HAProxy manual  
- **Cảnh báo SSL gần hết hạn:** Popup tự động khi login  
- **Auto renew:** Mỗi 12h, Certbot renew + copy PEM + reload HAProxy  

---

## 5. Ghi chú

- Certbot chạy standalone mode, port 80 phải mở  
- upload PEM → script `update_haproxy_certs.sh` tự copy + reload HAProxy  
- Tất cả thao tác SSL tự động, không cần thao tác thủ công
