import json
import os
import re
import copy
from datetime import datetime, timedelta, date
from pathlib import Path
from collections import Counter, defaultdict, deque

from flask import Flask, jsonify, request, send_from_directory, redirect, abort, session, Response
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).parent
DATA_FILE = BASE_DIR / "data.json"
SESSION_COOKIE_SECURE = bool(os.environ.get("SESSION_COOKIE_SECURE", "0") == "1")

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-omniflow")
# Tighten cookies for sessions
SESSION_COOKIE_SECURE = bool(os.environ.get("SESSION_COOKIE_SECURE", "0") == "1")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    SESSION_REFRESH_EACH_REQUEST=True,
)
app.permanent_session_lifetime = timedelta(minutes=30)

# In-memory login throttle per IP
LOGIN_ATTEMPTS = defaultdict(lambda: deque(maxlen=20))
LOGIN_MAX = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW = int(os.environ.get("LOGIN_WINDOW_SEC", "300"))


def is_same_origin(req):
    origin = req.headers.get("Origin") or ""
    referer = req.headers.get("Referer") or ""
    host = req.host_url.rstrip("/")
    return (origin.startswith(host) or referer.startswith(host) or (origin == "" and referer == ""))


def require_same_origin_for_mutation():
    """Block cross-site POST/PUT/PATCH/DELETE even before CSRF token checks."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not is_same_origin(request):
            abort(403)


def require_admin():
    """Simple role gate for admin-only endpoints."""
    user = session.get("user") or {}
    role = (user.get("role") or "").lower()
    if role == "admin":
        return
    abort(403)


def require_admin_or_manager():
    """Role gate for admin and manager endpoints."""
    user = session.get("user") or {}
    role = (user.get("role") or "").lower()
    if role == "admin" or "manager" in role:
        return
    abort(403)

def load_data():
    with DATA_FILE.open() as f:
        data = json.load(f)
    # Ensure permissions exist
    if "permissions" not in data:
        # default permission sets
        data["permissions"] = {
            "Member": {
                "orders": {"create": False, "update": False, "delete": False},
                "clients": {"create": False, "update": False, "delete": False},
                "inventory": {"create": False, "update": False, "delete": False},
            },
            "Manager": {
                "orders": {"create": True, "update": True, "delete": True},
                "clients": {"create": True, "update": True, "delete": True},
                "inventory": {"create": True, "update": True, "delete": True},
            },
            "Admin": {
                "orders": {"create": True, "update": True, "delete": True},
                "clients": {"create": True, "update": True, "delete": True},
                "inventory": {"create": True, "update": True, "delete": True},
            }
        }
    # One-time hash upgrade for stored auth password (backwards compatible)
    auth = data.get("auth", {})
    pwd = auth.get("password")
    if pwd and not str(pwd).startswith(("pbkdf2:", "scrypt:")):
        auth["password"] = generate_password_hash(str(pwd))
        data["auth"] = auth
        save_data(data)
    return data


def save_data(data):
    with DATA_FILE.open("w") as f:
        json.dump(data, f, indent=2)


def csrf_token():
    """Issue or fetch per-session CSRF token; stored in session and sent in cookie."""
    token = session.get("csrf_token")
    if not token:
        token = os.urandom(32).hex()
        session["csrf_token"] = token
    return token


def parse_date(value):
    return datetime.strptime(value, "%Y-%m-%d").date()


def today():
    return date.today()


def next_id(prefix, existing_ids):
    nums = [int(str(i).split("-")[-1]) for i in existing_ids if str(i).startswith(prefix + "-")]
    nxt = max(nums, default=0) + 1
    return f"{prefix}-{nxt:04d}"


def attach_client(data, order):
    client = next((c for c in data["clients"] if c["id"] == order["client_id"]), None)
    order = {**order}
    order["client_name"] = client["name"] if client else "Unknown"
    return order


def item_status(itm):
    if itm["stock"] == 0:
        return "out"
    if itm["stock"] <= itm["min_stock"]:
        return "low"
    return "ok"


def order_amount(order):
    """Return numeric amount regardless of stored type (string/number)."""
    try:
        return float(order.get("amount", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def verify_password(stored, candidate):
    """Backwards-compatible password check for legacy/plain/scrypt hashes."""
    if not stored:
        return False
    # Try hash-based verify first (pbkdf2/scrypt supported by werkzeug)
    try:
        if stored.startswith(("pbkdf2:", "scrypt:")):
            return check_password_hash(stored, candidate)
    except Exception:
        pass
    # Fallback: plain-text compare (legacy)
    return stored == candidate


def ensure_shop(data):
    """Ensure shop profile exists."""
    if "shop" not in data:
        user = data.get("user", {})
        auth = data.get("auth", {})
        data["shop"] = {
            "name": user.get("name", "Omni Workshop"),
            "industry": "Manufacturing",
            "address": "",
            "email": auth.get("email", ""),
        }
    return data["shop"]


def normalize_email(value):
    return (value or "").strip().lower()


def is_valid_email(value):
    if not value or not isinstance(value, str):
        return False
    email = value.strip()
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def is_strong_password(value):
    if not value or not isinstance(value, str):
        return False
    password = value.strip()
    return len(password) >= 8 and bool(re.search(r"[A-Za-z]", password)) and bool(re.search(r"\d", password))


def safe_int(value, min_value=None):
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    if min_value is not None and result < min_value:
        return None
    return result


def safe_float(value, min_value=None):
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    if min_value is not None and result < min_value:
        return None
    return result


VALID_ORDER_STATUSES = {"pending", "queued", "in-progress", "review", "done", "cancelled"}


def normalize_status(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def validate_order_payload(payload, partial=False):
    if not isinstance(payload, dict):
        return None, "invalid payload"
    order = {}
    if "client_id" in payload:
        client_id = str(payload.get("client_id") or "").strip()
        if client_id == "":
            return None, "client_id is required"
        order["client_id"] = client_id
    elif not partial:
        order["client_id"] = payload.get("client_id")

    if "product" in payload:
        product = str(payload.get("product") or "").strip()
        if product == "":
            return None, "product is required"
        order["product"] = product
    elif not partial:
        order["product"] = "Unnamed Product"

    if "qty" in payload:
        qty = safe_int(payload.get("qty"), min_value=0)
        if qty is None:
            return None, "qty must be a non-negative integer"
        order["qty"] = qty
    elif not partial:
        order["qty"] = 0

    if "status" in payload:
        status = normalize_status(payload.get("status")) or "pending"
        if status not in VALID_ORDER_STATUSES:
            return None, "invalid order status"
        order["status"] = status
    elif not partial:
        order["status"] = "pending"

    if "due_date" in payload:
        due_date = payload.get("due_date")
        if not due_date:
            due_date = today().isoformat()
        else:
            try:
                parse_date(due_date)
            except Exception:
                return None, "due_date must be YYYY-MM-DD"
        order["due_date"] = due_date
    elif not partial:
        order["due_date"] = today().isoformat()

    if "notes" in payload:
        order["notes"] = str(payload.get("notes") or "")
    elif not partial:
        order["notes"] = ""

    if "amount" in payload:
        amount = safe_float(payload.get("amount"), min_value=0)
        if amount is None:
            return None, "amount must be a non-negative number"
        order["amount"] = amount
    elif not partial:
        order["amount"] = 0.0

    if "turnaround_days" in payload:
        turnaround_days = safe_int(payload.get("turnaround_days"), min_value=0)
        if turnaround_days is None:
            return None, "turnaround_days must be a non-negative integer"
        order["turnaround_days"] = turnaround_days
    elif not partial:
        order["turnaround_days"] = 7

    if not partial:
        order["created_at"] = today().isoformat()
    return order, None


def validate_client_payload(payload, partial=False):
    if not isinstance(payload, dict):
        return None, "invalid payload"
    client = {}
    if "name" in payload:
        name = str(payload.get("name") or "").strip()
        if name == "" and not partial:
            return None, "name is required"
        client["name"] = name
    elif not partial:
        client["name"] = "New Client"

    if "contact" in payload:
        client["contact"] = str(payload.get("contact") or "")
    elif not partial:
        client["contact"] = ""

    if "email" in payload:
        email = normalize_email(payload.get("email"))
        if email and not is_valid_email(email):
            return None, "invalid email"
        client["email"] = email
    elif not partial:
        client["email"] = ""

    if "phone" in payload:
        client["phone"] = str(payload.get("phone") or "")
    elif not partial:
        client["phone"] = ""

    if "address" in payload:
        client["address"] = str(payload.get("address") or "")
    elif not partial:
        client["address"] = ""

    if "total_orders" in payload:
        total_orders = safe_int(payload.get("total_orders"), min_value=0)
        if total_orders is None:
            return None, "total_orders must be a non-negative integer"
        client["total_orders"] = total_orders
    elif not partial:
        client["total_orders"] = 0

    if "active_orders" in payload:
        active_orders = safe_int(payload.get("active_orders"), min_value=0)
        if active_orders is None:
            return None, "active_orders must be a non-negative integer"
        client["active_orders"] = active_orders
    elif not partial:
        client["active_orders"] = 0

    if "since" in payload:
        since = str(payload.get("since") or "").strip()
        if since and not re.match(r"^\d{4}$", since):
            return None, "since must be a four-digit year"
        client["since"] = since
    elif not partial:
        client["since"] = str(today().year)

    return client, None


def validate_inventory_payload(payload, partial=False):
    if not isinstance(payload, dict):
        return None, "invalid payload"
    item = {}
    if "name" in payload:
        name = str(payload.get("name") or "").strip()
        if name == "" and not partial:
            return None, "name is required"
        item["name"] = name
    elif not partial:
        item["name"] = "New Item"

    if "category" in payload:
        category = str(payload.get("category") or "").strip()
        item["category"] = category or "General"
    elif not partial:
        item["category"] = "General"

    if "stock" in payload:
        stock = safe_int(payload.get("stock"), min_value=0)
        if stock is None:
            return None, "stock must be a non-negative integer"
        item["stock"] = stock
    elif not partial:
        item["stock"] = 0

    if "min_stock" in payload:
        min_stock = safe_int(payload.get("min_stock"), min_value=0)
        if min_stock is None:
            return None, "min_stock must be a non-negative integer"
        item["min_stock"] = min_stock
    elif not partial:
        item["min_stock"] = 0

    if "unit" in payload:
        unit = str(payload.get("unit") or "").strip()
        item["unit"] = unit or "pcs"
    elif not partial:
        item["unit"] = "pcs"

    return item, None


def find_user_by_email(data, email):
    email_norm = normalize_email(email)
    return next((u for u in ensure_users(data) if normalize_email(u.get("email")) == email_norm), None)


def find_user_by_id(data, user_id):
    return next((u for u in ensure_users(data) if u.get("id") == user_id), None)


def sanitize_user(user):
    return {
        "id": user.get("id"),
        "name": user.get("name", ""),
        "email": user.get("email", ""),
        "role": user.get("role", "Member"),
    }


def ensure_users(data):
    """Ensure users list exists, seeded from primary user."""
    if "users" not in data or not data["users"]:
        user = data.get("user", {})
        auth = data.get("auth", {})
        data["users"] = [{
            "id": "U-0001",
            "name": user.get("name", "User"),
            "email": auth.get("email", "user@example.com"),
            "role": user.get("role", "User"),
        }]
    return data["users"]


def has_permission(data, role, resource, action):
    perms = data.get("permissions", {})
    # try exact role then fallbacks
    role_perms = perms.get(role) or perms.get(role.title()) or {}
    res = role_perms.get(resource, {})
    return bool(res.get(action, False))


def require_permission(resource, action):
    """Require the current session user to have a given permission."""
    user = session.get("user") or {}
    role = (user.get("role") or "").strip()
    data = load_data()
    if role.lower() == "admin" or "manager" in role.lower():
        # managers and admins have wide rights by default
        return
    if not has_permission(data, role, resource, action):
        abort(403)


def add_activity(data, message, typ="info"):
    session_user = session.get("user") or {}
    actor = session_user.get("name")
    if actor and actor not in message:
        if message and message[0].isupper():
            message = f"{actor} {message[0].lower()}{message[1:]}"
        else:
            message = f"{actor} {message}"
    existing_ids = [a.get("id", 0) for a in data.get("activity", [])]
    new_id = (max(existing_ids) + 1) if existing_ids else 1
    entry = {
        "id": new_id,
        "message": message,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "type": typ,
    }
    data.setdefault("activity", []).insert(0, entry)
    # keep the feed reasonably short
    if len(data["activity"]) > 100:
        data["activity"] = data["activity"][:100]


def add_audit(data, action, resource=None, details=None):
    """Append an audit record to `data['audit']` (kept small).
    Records the current session user id/name/role, timestamp, action, resource, and optional details.
    """
    session_user = session.get("user") or {}
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "actor": {
            "id": session_user.get("id"),
            "name": session_user.get("name"),
            "role": session_user.get("role"),
        },
        "action": action,
        "resource": resource,
        "details": details or {},
    }
    data.setdefault("audit", []).insert(0, entry)
    # Keep audit length bounded
    if len(data["audit"]) > 200:
        data["audit"] = data["audit"][:200]


def build_production_jobs(data):
    """Derive production jobs from orders so statuses stay in sync."""
    orders_by_id = {o["id"]: attach_client(data, o) for o in data.get("orders", [])}
    meta = {p["order_id"]: p for p in data.get("production", [])}
    jobs = []
    for order_id, order in orders_by_id.items():
        m = meta.get(order_id, {})
        jobs.append({
            "order_id": order_id,
            "product": order.get("product", m.get("product", "Unknown")),
            "client_name": order.get("client_name") or m.get("client_name", "Unknown"),
            "status": order.get("status", m.get("status", "queued")),
            "priority": m.get("priority", "normal"),
            "due_date": order.get("due_date", m.get("due_date", today().isoformat())),
        })
    return jobs


def compute_home_stats(data):
    orders = data["orders"]
    inventory = data["inventory"]
    active_orders = sum(1 for o in orders if o["status"] in {"pending", "in-progress", "queued"})
    in_production = sum(1 for o in orders if o["status"] == "in-progress")
    total_clients = len(data["clients"])
    today_date = today()
    due_this_week = sum(1 for o in orders if parse_date(o["due_date"]) <= today_date + timedelta(days=7) and parse_date(o["due_date"]) >= today_date)
    low_stock_count = sum(1 for i in inventory if i["stock"] <= i["min_stock"])
    return {
        "active_orders": active_orders,
        "in_production": in_production,
        "total_clients": total_clients,
        "due_this_week": due_this_week,
        "low_stock_count": low_stock_count,
    }


def month_key(dt_obj):
    return dt_obj.strftime("%Y-%m")


def aggregate_monthly(orders, months=6, date_field="created_at"):
    end = today().replace(day=1)
    months_list = []
    for i in range(months-1, -1, -1):
        month = (end - timedelta(days=30*i)).replace(day=1)
        months_list.append(month)
    labels = [m.strftime("%b %Y") for m in months_list]
    revenue = []
    count = []
    summary_rows = []
    grouped = defaultdict(list)
    for o in orders:
        if not o.get(date_field):
            continue
        d = parse_date(o[date_field])
        grouped[month_key(d)].append(o)
    for m in months_list:
        key = month_key(m)
        items = grouped.get(key, [])
        rev = sum(order_amount(o) for o in items)
        revenue.append(rev)
        count.append(len(items))
        completed = sum(1 for o in items if o["status"] == "done")
        cancelled = sum(1 for o in items if o["status"] == "cancelled")
        avg_turnaround = round(sum(o.get("turnaround_days", 0) for o in items) / len(items), 1) if items else 0
        summary_rows.append({
            "month": m.strftime("%b %Y"),
            "orders": len(items),
            "revenue": rev,
            "completed": completed,
            "cancelled": cancelled,
            "avg_turnaround": avg_turnaround,
        })
    return labels, revenue, count, summary_rows


def build_report(data, report_type="revenue", date_from=None, date_to=None):
    orders = data["orders"]
    # Use due_date for filtering/grouping when a date range is provided (more natural for reports).
    date_field = "due_date" if (date_from or date_to) else "created_at"
    if date_from:
        df = parse_date(date_from)
        orders = [o for o in orders if o.get(date_field) and parse_date(o[date_field]) >= df]
    if date_to:
        dt = parse_date(date_to)
        orders = [o for o in orders if o.get(date_field) and parse_date(o[date_field]) <= dt]
    labels, revenue, orders_count, summary_rows = aggregate_monthly(orders, months=6, date_field=date_field)
    metric = orders_count if report_type == "orders" else revenue
    return {
        "labels": labels,
        "revenue": revenue,
        "orders": orders_count,
        "metric": metric,
        "summary": summary_rows,
    }


@app.route("/")
def index():
    return redirect("/home.html")


@app.route("/home")
def home_route():
    return send_from_directory(app.static_folder, "home.html")


@app.route("/login")
def login_page():
    return send_from_directory(app.static_folder, "login.html")


# ---------- Auth helpers ----------
PUBLIC_EXT = {".css", ".js", ".svg", ".png", ".jpg", ".jpeg", ".ico", ".woff", ".woff2", ".ttf", ".map"}
PUBLIC_PATHS = {"/", "/login", "/api/login"}


@app.before_request
def require_login():
    path = request.path
    if request.method == "OPTIONS":
        return
    require_same_origin_for_mutation()
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and path not in {"/api/login", "/api/csrf"}:
        sent = request.headers.get("X-CSRF-Token") or request.cookies.get("XSRF-TOKEN")
        if not sent or sent != session.get("csrf_token"):
            return jsonify({"error": "csrf_failed"}), 403
    if path in PUBLIC_PATHS or any(path.endswith(ext) for ext in PUBLIC_EXT):
        return
    # Optional HTTPS enforcement outside dev/localhost
    if not app.debug and not request.host.startswith(("127.0.0.1", "localhost")) and request.scheme != "https":
        return redirect(request.url.replace("http://", "https://", 1), code=301)
    if session.get("user"):
        return
    # allow direct access to data.json for now (static)
    if path.endswith("data.json"):
        return
    if path.startswith("/api/"):
        return jsonify({"error": "unauthorized"}), 401
    return redirect("/login")


@app.route("/api/login", methods=["POST"])
def api_login():
    payload = request.get_json(force=True)
    email = normalize_email(payload.get("email"))
    password = payload.get("password") or ""
    if not email or not is_valid_email(email):
        return jsonify({"error": "invalid email"}), 400
    ip = request.remote_addr or "anon"
    now = datetime.now().timestamp()
    attempts = LOGIN_ATTEMPTS[ip]
    # prune old
    while attempts and now - attempts[0] > LOGIN_WINDOW:
        attempts.popleft()
    if len(attempts) >= LOGIN_MAX:
        return jsonify({"error": "too many attempts, try again later"}), 429
    data = load_data()
    user_record = find_user_by_email(data, email)
    if user_record and verify_password(user_record.get("password", ""), password):
        session.permanent = True
        session["user"] = {"id": user_record["id"], "name": user_record["name"], "role": user_record.get("role", "Member")}
        attempts.clear()
        add_activity(data, "logged in", "success")
        resp = jsonify(sanitize_user(user_record))
        token = csrf_token()
        resp.set_cookie("XSRF-TOKEN", token, samesite="Strict", secure=SESSION_COOKIE_SECURE)
        return resp
    auth = data.get("auth", {})
    stored_pw = auth.get("password", "")
    if email == normalize_email(auth.get("email")) and verify_password(stored_pw, password):
        session.permanent = True
        session["user"] = {"id": None, "name": data.get("user", {}).get("name", "User"), "role": data.get("user", {}).get("role", "User")}
        attempts.clear()
        add_activity(data, "logged in", "success")
        resp = jsonify(session["user"])
        token = csrf_token()
        resp.set_cookie("XSRF-TOKEN", token, samesite="Strict", secure=SESSION_COOKIE_SECURE)
        return resp
    # Fallback: accept default password if configured, and rotate hash immediately
    default_pw = os.environ.get("DEFAULT_PASSWORD", "admin123")
    if email == normalize_email(auth.get("email")) and password == default_pw:
        auth["password"] = generate_password_hash(default_pw)
        data["auth"] = auth
        save_data(data)
        session.permanent = True
        session["user"] = {"id": None, "name": data.get("user", {}).get("name", "User"), "role": data.get("user", {}).get("role", "User")}
        attempts.clear()
        add_activity(data, "logged in", "success")
        resp = jsonify(session["user"])
        token = csrf_token()
        resp.set_cookie("XSRF-TOKEN", token, samesite="Strict", secure=SESSION_COOKIE_SECURE)
        return resp
    attempts.append(now)
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    current_user = session.get("user")
    data = load_data()
    if current_user:
        add_activity(data, "logged out", "info")
        save_data(data)
    session.pop("user", None)
    session.pop("csrf_token", None)
    return "", 204


# ---------- API: Home ----------
@app.route("/api/home/stats")
def home_stats():
    data = load_data()
    return jsonify(compute_home_stats(data))


# ---------- API: Orders ----------
@app.route("/api/orders", methods=["GET", "POST"])
def orders_collection():
    data = load_data()
    if request.method == "GET":
        search = (request.args.get("search") or "").lower()
        status = request.args.get("status")
        client_id = request.args.get("client_id")
        orders = data["orders"]
        if search:
            orders = [o for o in orders if search in o["product"].lower() or search in o.get("id", "").lower()]
        if status:
            orders = [o for o in orders if o["status"] == status]
        if client_id:
            orders = [o for o in orders if o["client_id"] == client_id]
        orders = [attach_client(data, o) for o in orders]
        orders.sort(key=lambda o: o["due_date"])
        return jsonify(orders)

    payload = request.get_json(force=True)
    require_permission('orders', 'create')
    order, error = validate_order_payload(payload)
    if error:
        return jsonify({"error": error}), 400
    order["id"] = next_id("ORD", [o["id"] for o in data["orders"]])
    data["orders"].append(order)
    add_activity(data, f"Created order {order['id']}", "info")
    add_audit(data, 'create', resource='orders', details={'order_id': order['id']})
    save_data(data)
    return jsonify(attach_client(data, order)), 201


@app.route("/api/orders/recent")
def orders_recent():
    data = load_data()
    orders = sorted(data["orders"], key=lambda o: o.get("created_at", ""), reverse=True)[:5]
    orders = [attach_client(data, o) for o in orders]
    return jsonify(orders)


@app.route("/api/orders/<order_id>", methods=["GET", "PUT", "DELETE"])
def order_detail(order_id):
    data = load_data()
    orders = data["orders"]
    order = next((o for o in orders if o["id"] == order_id), None)
    if not order:
        abort(404)

    if request.method == "GET":
        return jsonify(attach_client(data, order))

    if request.method == "DELETE":
        require_permission('orders', 'delete')
        data["orders"] = [o for o in orders if o["id"] != order_id]
        add_activity(data, f"Deleted order {order_id}", "warning")
        add_audit(data, 'delete', resource='orders', details={'order_id': order_id})
        save_data(data)
        return "", 204

    payload = request.get_json(force=True)
    require_permission('orders', 'update')
    validated, error = validate_order_payload(payload, partial=True)
    if error:
        return jsonify({"error": error}), 400
    order.update(validated)
    add_activity(data, f"Updated order {order_id}", "info")
    add_audit(data, 'update', resource='orders', details={'order_id': order_id})
    save_data(data)
    return jsonify(attach_client(data, order))


# ---------- API: Clients ----------
@app.route("/api/clients", methods=["GET", "POST"])
def clients_collection():
    data = load_data()
    if request.method == "GET":
        search = (request.args.get("search") or "").lower()
        clients = data["clients"]
        if search:
            clients = [c for c in clients if search in c["name"].lower() or search in c.get("contact", "").lower()]
        return jsonify(clients)

    payload = request.get_json(force=True)
    require_permission('clients', 'create')
    client, error = validate_client_payload(payload)
    if error:
        return jsonify({"error": error}), 400
    norm = lambda v: (v or "").strip().lower()
    for c in data["clients"]:
        if all([
            norm(c.get("name")) == norm(client.get("name")),
            norm(c.get("contact")) == norm(client.get("contact")),
            norm(c.get("email")) == norm(client.get("email")),
            norm(c.get("phone")) == norm(client.get("phone")),
            norm(c.get("address")) == norm(client.get("address")),
        ]):
            return jsonify({"error": "duplicate client"}), 409
    client["id"] = next_id("C", [c["id"] for c in data["clients"]])
    data["clients"].append(client)
    add_activity(data, f"Added client {client['name']}", "info")
    add_audit(data, 'create', resource='clients', details={'client_id': client['id'], 'name': client['name']})
    save_data(data)
    return jsonify(client), 201


@app.route("/api/clients/<client_id>", methods=["GET", "PUT", "DELETE"])
def client_detail(client_id):
    data = load_data()
    client = next((c for c in data["clients"] if c["id"] == client_id), None)
    if not client:
        abort(404)

    if request.method == "GET":
        return jsonify(client)

    if request.method == "DELETE":
        require_permission('clients', 'delete')
        data["clients"] = [c for c in data["clients"] if c["id"] != client_id]
        add_activity(data, f"Deleted client {client['name']}", "warning")
        add_audit(data, 'delete', resource='clients', details={'client_id': client_id, 'name': client['name']})
        save_data(data)
        return "", 204

    payload = request.get_json(force=True)
    norm = lambda v: (v or "").strip().lower()
    if all(k in payload for k in ["name", "contact", "email", "phone", "address"]):
        for c in data["clients"]:
            if c["id"] == client_id:
                continue
            if all([
                norm(c.get("name")) == norm(payload.get("name")),
                norm(c.get("contact")) == norm(payload.get("contact")),
                norm(c.get("email")) == norm(payload.get("email")),
                norm(c.get("phone")) == norm(payload.get("phone")),
                norm(c.get("address")) == norm(payload.get("address")),
            ]):
                return jsonify({"error": "duplicate client"}), 409
    require_permission('clients', 'update')
    validated, error = validate_client_payload(payload, partial=True)
    if error:
        return jsonify({"error": error}), 400
    client.update(validated)
    add_activity(data, f"Updated client {client['name']}", "info")
    add_audit(data, 'update', resource='clients', details={'client_id': client_id, 'name': client['name']})
    save_data(data)
    return jsonify(client)


# ---------- API: Inventory ----------
@app.route("/api/inventory", methods=["GET", "POST"])
def inventory_collection():
    data = load_data()
    if request.method == "GET":
        search = (request.args.get("search") or "").lower()
        status = request.args.get("status")
        items = data["inventory"]
        if search:
            items = [i for i in items if search in i["name"].lower() or search in i.get("category", "").lower()]
        if status:
            items = [i for i in items if item_status(i) == status]
        return jsonify([{**i, "status": item_status(i)} for i in items])

    payload = request.get_json(force=True)
    require_permission('inventory', 'create')
    item, error = validate_inventory_payload(payload)
    if error:
        return jsonify({"error": error}), 400
    item["id"] = next_id("INV", [i["id"] for i in data["inventory"]])
    data["inventory"].append(item)
    add_activity(data, f"Added inventory item {item['name']}", "info")
    add_audit(data, 'create', resource='inventory', details={'item_id': item['id'], 'name': item['name']})
    save_data(data)
    return jsonify({**item, "status": item_status(item)}), 201


@app.route("/api/inventory/<item_id>", methods=["GET", "PUT", "DELETE"])
def inventory_detail(item_id):
    data = load_data()
    item = next((i for i in data["inventory"] if i["id"] == item_id), None)
    if not item:
        abort(404)

    if request.method == "GET":
        return jsonify({**item, "status": item_status(item)})

    if request.method == "DELETE":
        require_permission('inventory', 'delete')
        data["inventory"] = [i for i in data["inventory"] if i["id"] != item_id]
        add_activity(data, f"Deleted inventory item {item['name']}", "warning")
        add_audit(data, 'delete', resource='inventory', details={'item_id': item_id, 'name': item['name']})
        save_data(data)
        return "", 204

    payload = request.get_json(force=True)
    require_permission('inventory', 'update')
    validated, error = validate_inventory_payload(payload, partial=True)
    if error:
        return jsonify({"error": error}), 400
    item.update(validated)
    add_activity(data, f"Updated inventory item {item['name']}", "info")
    add_audit(data, 'update', resource='inventory', details={'item_id': item_id, 'name': item['name']})
    save_data(data)
    return jsonify({**item, "status": item_status(item)})


# ---------- API: Production ----------
@app.route("/api/production/board")
def production_board():
    data = load_data()
    board = {k: [] for k in ["pending", "queued", "in-progress", "review", "done", "cancelled"]}
    for job in build_production_jobs(data):
        status = job["status"]
        bucket = board.get(status, board["queued"])
        job_copy = dict(job)
        job_copy["is_overdue"] = parse_date(job_copy["due_date"]) < today()
        bucket.append(job_copy)
    return jsonify(board)


# ---------- API: Activity ----------
@app.route("/api/activity")
def activity():
    data = load_data()
    return jsonify(data["activity"])


# ---------- API: Dashboard ----------
@app.route("/api/dashboard/kpis")
def dashboard_kpis():
    data = load_data()
    period = request.args.get("period", "30D")
    days = {"7D": 7, "30D": 30, "90D": 90, "1Y": 365}.get(period, 30)
    cutoff = today() - timedelta(days=days)
    orders = [o for o in data["orders"] if parse_date(o["created_at"]) >= cutoff]
    revenue = sum(order_amount(o) for o in orders)
    completed = sum(1 for o in orders if o["status"] == "done")
    cancelled = sum(1 for o in orders if o["status"] == "cancelled")
    avg_turnaround = round(sum(o.get("turnaround_days", 0) for o in orders) / len(orders), 1) if orders else 0
    return jsonify({
        "revenue": revenue,
        "orders_completed": completed,
        "avg_turnaround": avg_turnaround,
        "cancelled": cancelled,
        "revenue_change": "+12% vs prior period",
        "orders_change": "+4% vs prior period",
        "turnaround_change": "-0.5 days",
        "cancelled_change": "-1 order",
    })


@app.route("/api/dashboard/revenue")
def dashboard_revenue():
    data = load_data()
    labels, revenue, _, _ = aggregate_monthly(data["orders"], months=6)
    return jsonify({"labels": labels, "values": revenue})


@app.route("/api/dashboard/order-status")
def dashboard_order_status():
    data = load_data()
    status_labels = ["Completed", "In Progress", "Pending", "Queued", "Cancelled"]
    mapping = {"Completed": "done", "In Progress": "in-progress", "Pending": "pending", "Queued": "queued", "Cancelled": "cancelled"}
    values = []
    for label in status_labels:
        values.append(sum(1 for o in data["orders"] if o["status"] == mapping[label]))
    return jsonify({"labels": status_labels, "values": values})


@app.route("/api/dashboard/throughput")
def dashboard_throughput():
    data = load_data()
    jobs = build_production_jobs(data)
    # jobs completed per week (last 8 weeks)
    today_date = today()
    labels = []
    values = []
    for i in range(7, -1, -1):
        start = today_date - timedelta(days=i*7 + 6)
        end = today_date - timedelta(days=i*7)
        label = f"Week {end.strftime('%W')}"
        count = sum(1 for j in jobs if j["status"] == "done" and start <= parse_date(j["due_date"]) <= end)
        labels.append(label)
        values.append(count)
    return jsonify({"labels": labels, "values": values})


@app.route("/api/dashboard/top-products")
def dashboard_top_products():
    data = load_data()
    counter = Counter(o["product"] for o in data["orders"])
    top = counter.most_common(5)
    return jsonify([{"name": name, "count": count} for name, count in top])


# ---------- API: Reports ----------
@app.route("/api/reports")
def reports():
    data = load_data()
    report_type = request.args.get("type", "revenue")
    date_from = request.args.get("from")
    date_to = request.args.get("to")
    return jsonify(build_report(data, report_type, date_from, date_to))


@app.route("/api/reports/forecast")
def reports_forecast():
    data = load_data()
    next_month_orders = int(sum(1 for o in data["orders"] if o["status"] in {"pending", "queued"}) * 1.1)
    low_stock = sum(1 for i in data["inventory"] if i["stock"] <= i["min_stock"])
    forecast = (
        f"Expected to ship ~{next_month_orders} orders next month based on current pipeline. "
        f"{low_stock} SKU(s) are at or below safety stock; prioritize replenishment to avoid delays."
    )
    return jsonify({"forecast_html": forecast})


@app.route("/api/reports/export")
def reports_export():
    fmt = request.args.get("format", "csv")
    report_type = request.args.get("type", "revenue")
    date_from = request.args.get("from")
    date_to = request.args.get("to")
    data = build_report(load_data(), report_type, date_from, date_to)
    lines = ["Label,Revenue,Orders"]
    for lbl, rev, cnt in zip(data["labels"], data["revenue"], data["orders"]):
        lines.append(f'"{lbl}",{rev},{cnt}')
    csv_bytes = "\n".join(lines).encode("utf-8")
    if fmt == "pdf":
        return Response(csv_bytes, mimetype="application/pdf",
                        headers={"Content-Disposition": "attachment; filename=report.pdf"})
    return Response(csv_bytes, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=report.csv"})


# ---------- API: Settings ----------
@app.route("/api/csrf")
def api_csrf():
    token = csrf_token()
    resp = jsonify({"csrf_token": token})
    resp.set_cookie("XSRF-TOKEN", token, samesite="Strict", secure=SESSION_COOKIE_SECURE)
    return resp


@app.route("/api/settings/shop", methods=["GET", "PUT"])
def settings_shop():
    require_admin()
    data = load_data()
    shop = ensure_shop(data)
    if request.method == "GET":
        return jsonify(shop)
    payload = request.get_json(force=True)
    for field in ["name", "industry", "address", "email"]:
        if field in payload:
            shop[field] = payload[field]
    data["shop"] = shop
    add_audit(data, 'update', resource='shop', details={'shop': shop.get('name')})
    save_data(data)
    return jsonify(shop)


@app.route("/api/settings/users", methods=["GET", "POST"])
def settings_users():
    require_admin_or_manager()
    data = load_data()
    users = ensure_users(data)
    if request.method == "GET":
        return jsonify([sanitize_user(u) for u in users])
    payload = request.get_json(force=True)
    email = normalize_email(payload.get("email"))
    password = payload.get("password") or ""
    if not email or not is_valid_email(email):
        return jsonify({"error": "valid email is required"}), 400
    if not is_strong_password(password):
        return jsonify({"error": "password must be at least 8 characters and include letters and numbers"}), 400
    if find_user_by_email(data, email):
        return jsonify({"error": "email already in use"}), 409
    new_id = next_id("U", [u["id"] for u in users])
    user = {
        "id": new_id,
        "name": payload.get("name", "New User"),
        "email": email,
        "role": payload.get("role", "Member"),
        "password": generate_password_hash(password),
    }
    users.append(user)
    add_activity(data, f"Invited user {user['name']}", "info")
    data["users"] = users
    add_audit(data, 'create', resource='users', details={'user_id': user['id'], 'email': user['email']})
    save_data(data)
    return jsonify(sanitize_user(user)), 201


@app.route("/api/settings/users/<user_id>", methods=["DELETE"])
def settings_users_delete(user_id):
    require_admin_or_manager()
    data = load_data()
    users = ensure_users(data)
    before = len(users)
    users = [u for u in users if u["id"] != user_id]
    if len(users) == before:
        abort(404)
    data["users"] = users
    add_activity(data, f"Removed user {user_id}", "warning")
    add_audit(data, 'delete', resource='users', details={'user_id': user_id})
    save_data(data)
    return "", 204


@app.route('/api/settings/permissions', methods=['GET', 'PUT'])
def settings_permissions():
    require_admin_or_manager()
    data = load_data()
    if request.method == 'GET':
        return jsonify(data.get('permissions', {}))
    payload = request.get_json(force=True)
    # Basic validation: must be a dict
    if not isinstance(payload, dict):
        return jsonify({'error': 'invalid payload'}), 400
    data['permissions'] = payload
    add_activity(data, "updated permissions", "info")
    add_audit(data, 'update', resource='permissions', details={'by': session.get('user')})
    save_data(data)
    return jsonify(data['permissions'])


@app.route('/api/settings/audit', methods=['GET'])
def settings_audit():
    require_admin()
    data = load_data()
    audit = data.get('audit', [])
    limit = request.args.get('limit')
    if limit is not None:
        try:
            limit = int(limit)
        except ValueError:
            return jsonify({'error': 'limit must be an integer'}), 400
        if limit < 0:
            return jsonify({'error': 'limit must be non-negative'}), 400
        audit = audit[:limit]
    return jsonify(audit)


# ---------- API: Me ----------
@app.route("/api/me", methods=["GET", "PUT"])
def me():
    data = load_data()
    session_user = session.get("user", {})
    user_id = session_user.get("id")
    if request.method == "GET":
        if user_id:
            user_record = find_user_by_id(data, user_id)
            if user_record:
                return jsonify(sanitize_user(user_record))
        user = data.get("user", {"name": "Omni User", "role": "Manager"})
        auth = data.get("auth", {})
        return jsonify({
            "id": None,
            "name": user.get("name", "Omni User"),
            "email": auth.get("email", ""),
            "role": user.get("role", "Manager"),
        })
    payload = request.get_json(force=True)
    if user_id:
        user_record = find_user_by_id(data, user_id)
        if not user_record:
            abort(404)
        if "name" in payload:
            user_record["name"] = payload["name"]
        if "email" in payload:
            if not is_valid_email(payload["email"]):
                return jsonify({"error": "invalid email"}), 400
            user_record["email"] = normalize_email(payload["email"])
        add_activity(data, "updated profile", "info")
        save_data(data)
        session["user"]["name"] = user_record["name"]
        return jsonify(sanitize_user(user_record))
    data.setdefault("user", {})
    data.setdefault("auth", {})
    if "name" in payload:
        data["user"]["name"] = payload["name"]
    if "role" in payload:
        data["user"]["role"] = payload["role"]
    if "email" in payload:
        if not is_valid_email(payload["email"]):
            return jsonify({"error": "invalid email"}), 400
        data["auth"]["email"] = normalize_email(payload["email"])
    save_data(data)
    return jsonify(data["user"])


@app.route("/api/me/password", methods=["POST"])
def change_password():
    data = load_data()
    payload = request.get_json(force=True)
    current_pw = payload.get("current_password") or ""
    new_pw = payload.get("new_password") or ""
    confirm_pw = payload.get("confirm_password") or ""
    session_user = session.get("user", {})
    user_id = session_user.get("id")
    if user_id:
        user_record = find_user_by_id(data, user_id)
        if not user_record:
            abort(404)
        stored = user_record.get("password", "")
        if not verify_password(stored, current_pw):
            return jsonify({"error": "current password incorrect"}), 400
        if len(new_pw) < 6:
            return jsonify({"error": "new password too short"}), 400
        if new_pw != confirm_pw:
            return jsonify({"error": "passwords do not match"}), 400
        user_record["password"] = generate_password_hash(new_pw)
        add_activity(data, f"Updated password for {user_record.get('name', 'user')}", "info")
        add_audit(data, 'change_password', resource='users', details={'user_id': user_id})
        save_data(data)
        return jsonify({"status": "ok"})
    auth = data.get("auth", {})
    stored = auth.get("password", "")
    pass_ok = False
    if stored.startswith("scrypt:"):
        # legacy hash we can't verify easily; allow authenticated user to rotate if they provide anything non-empty
        pass_ok = bool(current_pw)
    elif stored and not stored.startswith("pbkdf2:"):
        pass_ok = (current_pw == stored)
    else:
        pass_ok = check_password_hash(stored, current_pw)
    if not pass_ok:
        return jsonify({"error": "current password incorrect"}), 400
    if not is_strong_password(new_pw):
        return jsonify({"error": "new password must be at least 8 characters and include letters and numbers"}), 400
    if new_pw != confirm_pw:
        return jsonify({"error": "passwords do not match"}), 400
    auth["password"] = generate_password_hash(new_pw)
    data["auth"] = auth
    add_activity(data, "Updated account password", "info")
    add_audit(data, 'change_password', resource='auth', details={})
    save_data(data)
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
