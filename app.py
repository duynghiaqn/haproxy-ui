from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import os, subprocess, datetime, threading, json

app = Flask(__name__)
app.secret_key = "91872df8b381edb66aee61c9dbd0ac7b5e8c8f39e3f29f7be3f81359311c15c1"

ADMIN_USER = "admin"
ADMIN_PASS = "admin"

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("Vui lòng đăng nhập!", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ----------------- Paths -----------------
CERTS_DIR = "/opt/haproxy_manager/certs"
CRT_LIST = "/opt/haproxy_manager/crt-list.txt"
DOMAINS_FILE = "/opt/haproxy_manager/domains.map"
BACKENDS_FILE = "/opt/haproxy_manager/backends.json"
SECURITY_FILE = "/opt/haproxy_manager/security.json"
UPDATE_SCRIPT = "/opt/haproxy_manager/update_haproxy_certs.sh"

os.makedirs(CERTS_DIR, exist_ok=True)
for f in [DOMAINS_FILE, CRT_LIST, BACKENDS_FILE, SECURITY_FILE]:
    if not os.path.exists(f): open(f,"w").close()

# --- Load security settings ---
def load_security():
    if not os.path.exists(SECURITY_FILE):
        default = {"protocols":"TLSv1.2+TLSv1.3","ciphers":"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
                   "hsts":True,"rate_limit":100,"xss_protect":True}
        with open(SECURITY_FILE,"w") as f: json.dump(default,f)
        return default
    with open(SECURITY_FILE) as f:
        return json.load(f)

# --- Security page ---
@app.route("/security", methods=["GET", "POST"])
@login_required
def security_page():
    # Nếu POST → cập nhật cấu hình
    if request.method == "POST":
        settings = {
            "protocols": request.form.get("protocols"),
            "ciphers": request.form.get("ciphers"),
            "hsts": True if request.form.get("hsts")=="on" else False,
            "rate_limit": int(request.form.get("rate_limit") or 100),
            "xss_protect": True if request.form.get("xss_protect")=="on" else False
        }
        with open(SECURITY_FILE,"w") as f:
            json.dump(settings,f)
        flash("Security settings updated!", "success")
        # Reload HAProxy để áp dụng cấu hình mới
        subprocess.run(["sudo", UPDATE_SCRIPT], check=True)
        return redirect(url_for("security_page"))

    # Nếu GET → load settings và hiển thị
    settings = {}
    if os.path.exists(SECURITY_FILE):
        with open(SECURITY_FILE) as f:
            settings = json.load(f)
    return render_template("security.html", settings=settings)
# ----------------- Helper Functions -----------------
def get_cert_expiry(pem_file):
    try:
        out = subprocess.check_output(["openssl","x509","-enddate","-noout","-in",pem_file]).decode()
        date_str = out.strip().split("=",1)[1]
        return datetime.datetime.strptime(date_str,"%b %d %H:%M:%S %Y %Z")
    except: return None

def load_domains():
    if os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE) as f:
            return [l.strip() for l in f if l.strip()]
    return []

def load_backends():
    if os.path.exists(BACKENDS_FILE):
        with open(BACKENDS_FILE) as f:
            return json.load(f)
    return []

def save_backends(backends):
    with open(BACKENDS_FILE,"w") as f:
        json.dump(backends,f,indent=4)
    update_haproxy_cfg()

def load_security_config():
    if os.path.exists(SECURITY_FILE):
        with open(SECURITY_FILE) as f:
            return json.load(f)
    return {}

def save_security_config(cfg):
    with open(SECURITY_FILE,"w") as f:
        json.dump(cfg,f,indent=4)
    update_haproxy_cfg()

def update_haproxy_cfg():
    backends = load_backends()
    security = load_security_config()

    frontend_lines = [
        "frontend https_front",
        f"    bind *:443 ssl crt-list {CRT_LIST} "
        f"ssl-min-ver TLSv1.2 ciphers {security.get('ssl_ciphers','ECDHE-RSA-AES256-GCM-SHA384')}",
        "    mode http",
        "    default_backend web_back"
    ]
    if security.get("hsts"):
        frontend_lines.append('    http-response set-header Strict-Transport-Security "max-age=31536000"')
    if security.get("x_frame_options"):
        frontend_lines.append(f'    http-response set-header X-Frame-Options "{security.get("x_frame_options")}"')
    if security.get("x_xss_protection"):
        frontend_lines.append(f'    http-response set-header X-XSS-Protection "{security.get("x_xss_protection")}"')
    if security.get("csp"):
        frontend_lines.append(f'    http-response set-header Content-Security-Policy "{security.get("csp")}"')

    backend_lines = ["backend web_back", "    mode http", "    balance roundrobin"]
    for b in backends:
        line = f"    server {b['name']} {b['ip']}:{b['port']}"
        if b.get("ssl"): line += " ssl verify none"
        line += " check"
        backend_lines.append(line)

    with open("/etc/haproxy/haproxy.cfg","w") as f:
        for line in frontend_lines+[""]+backend_lines:
            f.write(line+"\n")

    subprocess.run(["sudo",UPDATE_SCRIPT], check=True)

# ----------------- Routes -----------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("username")==ADMIN_USER and request.form.get("password")==ADMIN_PASS:
            session["logged_in"]=True
            flash("Đăng nhập thành công!","success")
            return redirect(url_for("index"))
        flash("Sai username hoặc password","error")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in",None)
    flash("Đã đăng xuất!","info")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    domains = load_domains()
    backends = load_backends()
    security = load_security_config()

    certs_info=[]
    expiring_certs=[]
    now_dt=datetime.datetime.now()
    for d in domains:
        pem_file=os.path.join(CERTS_DIR,f"{d}.pem")
        expire=get_cert_expiry(pem_file)
        status="OK" if expire and expire>now_dt else "Expired"
        certs_info.append({"domain":d,"pem":pem_file if os.path.exists(pem_file) else None,
                           "expire":expire,"status":status})
        if expire and (expire-now_dt).days<30:
            expiring_certs.append({"domain":d,"days_left":(expire-now_dt).days})
    return render_template("index.html", certs=certs_info, expiring_certs=expiring_certs,
                           backends=backends, security=security, now=now_dt)

# -------- Domain ----------
@app.route("/add_domain", methods=["POST"])
@login_required
def add_domain():
    domain=request.form.get("domain","").strip()
    if not domain: flash("Domain không hợp lệ!","error"); return redirect(url_for("index"))
    with open(DOMAINS_FILE,"a") as f: f.write(domain+"\n")
    flash(f"Domain {domain} đã thêm!","success")
    return redirect(url_for("index"))

@app.route("/delete_domain/<domain>", methods=["POST"])
@login_required
def delete_domain(domain):
    domain=domain.strip()
    if os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE) as f:
            lines=[l.strip() for l in f if l.strip() and l.strip()!=domain]
        with open(DOMAINS_FILE,"w") as f: f.write("\n".join(lines)+"\n")
    pem_file=os.path.join(CERTS_DIR,f"{domain}.pem")
    if os.path.exists(pem_file): os.remove(pem_file)
    subprocess.run(["sudo",UPDATE_SCRIPT], check=True)
    flash(f"Domain {domain} đã xóa!","success")
    return redirect(url_for("index"))

# -------- Backend ----------
@app.route("/add_backend", methods=["POST"])
@login_required
def add_backend():
    data=request.form
    backend={
        "name":data["name"],
        "ip":data["ip"],
        "port":int(data["port"]),
        "ssl":data.get("ssl")=="on"
    }
    backends=load_backends()
    backends.append(backend)
    save_backends(backends)
    flash(f"Backend {backend['name']} đã thêm!","success")
    return redirect(url_for("index"))

@app.route("/delete_backend", methods=["POST"])
@login_required
def delete_backend():
    name=request.form["name"]
    backends=load_backends()
    backends=[b for b in backends if b["name"]!=name]
    save_backends(backends)
    flash(f"Backend {name} đã xóa!","success")
    return redirect(url_for("index"))

# -------- PEM / SSL ----------
@app.route("/upload_pem", methods=["POST"])
@login_required
def upload_pem():
    domain=request.form.get("domain","").strip()
    pem=request.files.get("pem")
    if not domain or not pem:
        flash("Domain hoặc PEM không hợp lệ!","error")
        return redirect(url_for("index"))
    pem_path=os.path.join(CERTS_DIR,f"{domain}.pem")
    pem.save(pem_path)
    os.chmod(pem_path,0o600)
    subprocess.run(["sudo",UPDATE_SCRIPT], check=True)
    flash(f"Upload PEM thành công cho {domain}","success")
    return redirect(url_for("index"))

@app.route("/renew_ssl/<domain>", methods=["POST"])
@login_required
def renew_ssl(domain):
    domain=domain.strip()
    pem_file=os.path.join(CERTS_DIR,f"{domain}.pem")
    try:
        subprocess.run([
            "certbot","certonly","--standalone","--non-interactive",
            "--agree-tos","-m","admin@example.org","-d",domain
        ], check=True)
        live_dir=f"/etc/letsencrypt/live/{domain}"
        if os.path.exists(live_dir):
            with open(pem_file,"wb") as out:
                out.write(open(os.path.join(live_dir,"fullchain.pem"),"rb").read())
                out.write(open(os.path.join(live_dir,"privkey.pem"),"rb").read())
            os.chmod(pem_file,0o600)
        subprocess.run(["sudo",UPDATE_SCRIPT], check=True)
        flash(f"Gia hạn SSL thành công cho {domain}","success")
    except Exception as e:
        flash(f"Gia hạn SSL thất bại cho {domain}: {e}","error")
    return redirect(url_for("index"))

@app.route("/reload", methods=["POST"])
@login_required
def do_reload():
    subprocess.run(["sudo",UPDATE_SCRIPT], check=True)
    flash("Reload HAProxy thành công!","success")
    return redirect(url_for("index"))

# -------- Security ----------
@app.route("/security", methods=["GET","POST"])
@login_required
def security():
    if request.method=="POST":
        cfg={
            "ssl_protocols":request.form.get("ssl_protocols"),
            "ssl_ciphers":request.form.get("ssl_ciphers"),
            "hsts":request.form.get("hsts")=="on",
            "x_frame_options":request.form.get("x_frame_options"),
            "x_xss_protection":request.form.get("x_xss_protection"),
            "csp":request.form.get("csp")
        }
        save_security_config(cfg)
        flash("Cấu hình bảo mật đã cập nhật","success")
        return redirect(url_for("index"))
    cfg=load_security_config()
    return render_template("security.html", cfg=cfg)
#------------------------------------------
@app.route("/haproxy_action/<action>", methods=["POST"])
@login_required
def haproxy_action(action):
    action = action.lower()
    if action not in ["start", "stop", "reload"]:
        flash("Hành động không hợp lệ!", "error")
        return redirect(url_for("index"))
    try:
        subprocess.run(["sudo", UPDATE_SCRIPT, action], check=True)
        flash(f"HAProxy {action} thành công!", "success")
    except Exception as e:
        flash(f"HAProxy {action} thất bại: {e}", "error")
    return redirect(url_for("index"))


# -------- Auto SSL renew thread ----------
def auto_renew_ssl():
    import time
    while True:
        domains=load_domains()
        for d in domains:
            pem_file=os.path.join(CERTS_DIR,f"{d}.pem")
            try:
                subprocess.run([
                    "certbot","certonly","--standalone","--non-interactive",
                    "--agree-tos","-m","admin@example.org","-d",d
                ], check=True)
                live_dir=f"/etc/letsencrypt/live/{d}"
                if os.path.exists(live_dir):
                    with open(pem_file,"wb") as out:
                        out.write(open(os.path.join(live_dir,"fullchain.pem"),"rb").read())
                        out.write(open(os.path.join(live_dir,"privkey.pem"),"rb").read())
                    os.chmod(pem_file,0o600)
                subprocess.run(["sudo",UPDATE_SCRIPT], check=True)
            except: pass
        time.sleep(12*3600)

threading.Thread(target=auto_renew_ssl, daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

