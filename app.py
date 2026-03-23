# --- stdlib
import os, re, json, uuid, random, time, tempfile, urllib.parse, traceback, hmac, base64, hashlib
import requests
from uuid import uuid4, UUID
from uuid import uuid4, UUID
from datetime import datetime, timezone as dt_timezone

# --- third party
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash, send_from_directory, Response  # ← 沒有 Markup
from markupsafe import Markup
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client
from postgrest.exceptions import APIError
from flask_mail import Mail, Message
from dateutil import parser
from dotenv import load_dotenv
from pytz import timezone as pytz_timezone
from utils import generate_ecpay_form 
from datetime import timedelta
import secrets
from authlib.integrations.flask_client import OAuth
from flask import abort
import re, secrets
from flask import current_app
from flask import Flask, redirect, url_for, request, session, current_app
from line_notify import send_line_order_notify
from line_notify import send_line_message_notify


DEFAULT_SHELL_IMAGE = "/static/uploads/logo_0.png"
# （刪掉重複的 import traceback；上面第一行已經有了）
TW = pytz_timezone("Asia/Taipei")


load_dotenv()

# --- after load_dotenv() ---
app = Flask(__name__, static_folder="static", template_folder="templates")

from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# 建議放到環境變數；先給一個後備值避免部署當下報錯
# ✅ 建議：Production 一定要在 Render 設環境變數 FLASK_SECRET_KEY
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret")

# ✅ 重新設定 Cookie 政策（host-only domain、避免跨網域掉 Cookie）
from datetime import timedelta
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",   # 預設 Lax 可在頂層導覽時帶 cookie
    SESSION_COOKIE_SECURE=True,      # 僅在 HTTPS 下傳送
    SESSION_COOKIE_HTTPONLY=True,    # JS 不能讀，較安全
    PREFERRED_URL_SCHEME="https",    # url_for 生成 https
)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

@app.before_request
def _force_primary_host():
    # 只允許正式主機，其他一律 301 轉到正式站，避免 session 分裂
    primary = "herset.co"
    host = request.host.split(":")[0]
    if host != primary:
        url = f"https://{primary}{request.full_path}"
        if url.endswith("?"):
            url = url[:-1]
        return redirect(url, code=301)

# === LINE Pay 設定（正式環境）===
LINE_PAY_CHANNEL_ID = os.getenv("LINE_PAY_CHANNEL_ID")  # ← 放正式的 Channel ID
LINE_PAY_CHANNEL_SECRET = os.getenv("LINE_PAY_CHANNEL_SECRET")  # ← 放正式的 Secret
LINE_PAY_BASE = os.getenv("LINE_PAY_BASE", "https://api-pay.line.me")  # ← 改成正式網域

LINE_PAY_REQUEST_URL = f"{LINE_PAY_BASE}/v3/payments/request"
LINE_PAY_CONFIRM_URL = f"{LINE_PAY_BASE}/v3/payments/{{transactionId}}/confirm"

# 站點外部可訪問網址（給 LINE Pay redirect 回來）
SITE_BASE_URL = os.getenv("SITE_BASE_URL") or os.getenv("RENDER_EXTERNAL_URL")  # ← 必須是正式 https 網域

# ---- helpers ------------------------------------------------------------
def _clean_bundle_label(s: str) -> str:
    if not s:
        return ""
    s = str(s)
    s = re.sub(r'^\s*#?\s*\d+\s*', '', s)   # 去掉開頭的 #1 / 1 等標號
    s = s.replace('／', ' / ')              # 全形斜線換成半形，前後加空白
    s = re.sub(r'\s{2,}', ' ', s)           # 連續空白壓成一個
    return s.strip()

# 新增：把 <input type="datetime-local"> 的台灣時間轉成 UTC ISO
def to_utc_iso_from_tw(local_str: str):
    if not local_str:
        return None
    dt = datetime.strptime(local_str, "%Y-%m-%dT%H:%M")
    dt_tw = TW.localize(dt)
    return dt_tw.astimezone(dt_timezone.utc).isoformat()

ALNUM = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # 避免易混淆字母可再縮減
def generate_merchant_trade_no(prefix="HS", rand_len=8):
    """
    產生像 HS2509019XQ4MZ7P 的編號：
    - HS   : 自訂前綴
    - YYMMDD: 台北時間日期
    - 隨機英數: 長度 rand_len（預設 8）
    全長 2 + 6 + 8 = 16（< 20，符合綠界限制）
    會簡單查 DB 避免碰撞，極少機率重生一次。
    """
    date = datetime.now(TW).strftime("%y%m%d")
    rand = ''.join(secrets.choice(ALNUM) for _ in range(rand_len))
    trade_no = f"{prefix}{date}{rand}"

    # 確認不重複（極小機率才會再生一次）
    try:
        exists = (supabase.table("orders")
                  .select("id").eq("MerchantTradeNo", trade_no)
                  .limit(1).execute().data)
        if exists:
            return generate_merchant_trade_no(prefix, rand_len)
    except Exception:
        pass
    return trade_no

def _money(v) -> int:
    try:
        return int(Decimal(str(v or 0)).quantize(Decimal('1'), rounding=ROUND_HALF_UP))
    except Exception:
        return int(round(float(v or 0)))

# ✅ 正確：第二參數是「已序列化」的 JSON 字串（POST 傳 body；GET 傳 querystring；沒有就空字串）
def _lp_signature_headers(request_uri: str, serialized: str, method: str = "POST"):
    nonce = str(uuid4())
    message = (LINE_PAY_CHANNEL_SECRET + request_uri + (serialized or "") + nonce).encode("utf-8")
    signature = base64.b64encode(
        hmac.new(LINE_PAY_CHANNEL_SECRET.encode("utf-8"), message, hashlib.sha256).digest()
    ).decode("utf-8")
    return {
        "Content-Type": "application/json",
        "X-LINE-ChannelId": LINE_PAY_CHANNEL_ID,
        "X-LINE-Authorization-Nonce": nonce,
        "X-LINE-Authorization": signature,
    }

#用第三方資料找或建會員的 helper
def _sanitize_username(s: str) -> str:
    """把姓名或 email local-part 轉成合規 username（僅 a-zA-Z0-9_.-，長度<=30）"""
    s = (s or "").strip()
    s = re.sub(r"\s+", "_", s)                 # 空白轉底線
    s = re.sub(r"[^a-zA-Z0-9_.-]", "", s)     # 只留允許字元
    return s[:30]

def _pick_username(provider: str, sub: str, email: str | None, name: str | None) -> str:
    candidates = []
    if name:
        candidates.append(_sanitize_username(name))
    if email and "@" in email:
        candidates.append(_sanitize_username(email.split("@", 1)[0]))
    # 保底
    candidates.append(f"{provider}_{(sub or '')[:8]}")

    # 從候選逐一檢查是否已存在，存在就加序號
    for base in candidates:
        if not base:
            continue
        username = base
        i = 1
        while True:
            q = supabase.table("members").select("id").eq("username", username).limit(1).execute()
            if not q.data:     # 沒撞名就用它
                return username
            i += 1
            suffix = str(i)
            username = (base[: (30 - len(suffix))] + suffix)
    # 理論上不會走到這
    return f"{provider}_{secrets.token_hex(4)}"

def upsert_member_from_oauth(*, provider: str, sub: str, email: str | None, name: str | None, avatar_url: str | None):
    """
    以 OAuth 登入資料建立/回傳會員。
    判斷原則：
      1) 先用 (oauth_provider, oauth_sub) 找到原本的 OAuth 帳號
      2) 再用 email 找（可能為 None）
    以「第一次寫入」為主：既有帳號出現時，不回填/覆蓋 signup_method 與 oauth_*。
    """
    existing = None
    if provider and sub:
        r = (supabase.table("members").select("*")
             .eq("oauth_provider", provider).eq("oauth_sub", sub)
             .limit(1).execute())
        if r.data:
            existing = r.data[0]

    if not existing and email:
        r = supabase.table("members").select("*").eq("email", email).limit(1).execute()
        if r.data:
            existing = r.data[0]

    if existing:
        updates = {}
        # ✅ 不覆蓋 signup_method（以第一次為準）
        # ✅ 也不把平台帳號回填成 oauth_provider/oauth_sub（避免標籤變動）
        if name and not existing.get("name"):
            updates["name"] = name
        if avatar_url and not existing.get("avatar_url"):
            updates["avatar_url"] = avatar_url
        if updates:
            supabase.table("members").update(updates).eq("id", existing["id"]).execute()
            existing.update(updates)
        return existing

    # 建立新會員（這是「第一次寫入」）
    username = _pick_username(provider, sub or "", email, name)
    payload = {
        "username": username,
        "email": email,
        "name": name or username,
        "oauth_provider": provider,
        "oauth_sub": sub,
        "avatar_url": avatar_url,
        "signup_method": provider or "platform",   # ✅ 第一次即定案
    }
    created = supabase.table("members").insert(payload).execute()
    return created.data[0]

# === Wallet / Credits helpers ===
def _wallet_settings():
    amount_nt = get_setting_num("wallet_signup_amount_nt", 0)
    valid_days = int(get_setting_num("wallet_signup_valid_days", 0))
    min_order_amount = get_setting_num("wallet_min_order_amount_nt", 0)

    return {
        "amount_cents": int(round(float(amount_nt) * 100)),
        "valid_days": max(0, valid_days),
        "min_order_amount": int(float(min_order_amount)),

    }



def _get_wallet_balance(member_id: str) -> int:
    """回傳目前餘額（cents），沒有就 0"""
    try:
        r = (supabase.table("wallet_balances")
             .select("balance_cents").eq("member_id", member_id)
             .limit(1).execute())
        if r.data:
            return int(r.data[0].get("balance_cents") or 0)
    except Exception:
        pass
    return 0

def _grant_wallet(member_id: str, amount_cents: int, *, reason: str,
                  expires_at_iso: str | None = None,
                  issued_by_admin: str | None = None,
                  note: str | None = None) -> bool:
    """發放購物金：寫 wallet_credits 並更新 wallet_balances"""
    if not member_id or not isinstance(amount_cents, int) or amount_cents <= 0:
        return False
    try:
        # 1) 建交易明細
        supabase.table("wallet_credits").insert({
            "member_id": member_id,
            "amount_cents": amount_cents,
            "reason": reason,
            "expires_at": expires_at_iso,
            "issued_by_admin": issued_by_admin,
            "note": note
    }, returning="minimal").execute()
        # 2) 更新餘額（簡單兩段式；若要完全避免競爭以 SQL function 取代）
        cur = _get_wallet_balance(member_id)
        new_balance = cur + amount_cents
        supabase.table("wallet_balances").upsert({
            "member_id": member_id,
            "balance_cents": new_balance
        }, returning="minimal").execute()
        return True
    except Exception as e:
        current_app.logger.exception("[wallet] grant failed: %s", e)
        return False

def _has_signup_granted(member_id: str) -> bool:
    """是否已發過新會員購物金（用 reason='signup_bonus' 判斷）"""
    try:
        r = (supabase.table("wallet_credits")
             .select("id").eq("member_id", member_id)
             .eq("reason", "signup_bonus")
             .limit(1).execute())
        return bool(r.data)
    except Exception:
        return False

def _auto_grant_signup_wallet(member_id: str):
    """第一次登入/註冊自動發放（若設定金額 > 0 且尚未發過）"""
    cfg = _wallet_settings()
    amt = int(cfg["amount_cents"])
    if amt <= 0 or not member_id:
        return
    if _has_signup_granted(member_id):
        return
    # 過期日
    expires_iso = None
    days = int(cfg["valid_days"] or 0)
    if days > 0:
        expires_iso = (datetime.utcnow() + timedelta(days=days)).isoformat()
    ok = _grant_wallet(member_id, amt, reason="signup_bonus",
                       expires_at_iso=expires_iso, issued_by_admin=None,
                       note="新會員自動發放")
    if ok:
        current_app.logger.info("[wallet] signup bonus granted to %s, %s cents", member_id, amt)

# === Wallet helpers: 取餘額（從 table 或用 SUM 計算，擇一，依你現在 DB 為準） ===
def _get_wallet_balance_cents(member_id: str) -> int:
    """
    回傳會員當前購物金（cents）。
    若你的 wallet_balances 是 table → 走 table；
    若它是 VIEW（不能寫入）→ 直接從 wallet_credits 加總。
    """
    try:
        # 如果你已把 wallet_balances 改成「table」，用這段：
        res = (supabase.table("wallet_balances")
               .select("balance_cents")
               .eq("member_id", member_id)
               .limit(1).execute())
        return max(int((res.data or [{}])[0].get("balance_cents") or 0), 0)
    except Exception:
        # 若上面失敗（或你保留 balances 為 VIEW），退回用 credits 加總
        res = (supabase.table("wallet_credits")
               .select("amount_cents")
               .eq("member_id", member_id).execute())
        return max(sum(int(r.get("amount_cents") or 0) for r in (res.data or [])), 0)


def _refresh_wallet_badge(member_id: str) -> None:
    """把最新餘額塞回 session，給頁首徽章使用。"""
    try:
        session["wallet_balance_cents"] = _get_wallet_balance_cents(member_id)
    except Exception:
        session["wallet_balance_cents"] = 0


# ★ 保險：每個請求若已登入但 session 沒該值，就補一次
@app.before_request
def _ensure_wallet_badge():
    mid = session.get("member_id")
    if mid and "wallet_balance_cents" not in session:
        _refresh_wallet_badge(mid)

#刷新購物金到 session
def _refresh_wallet_session(member_id: str) -> int:
    """
    從 DB 讀取最新餘額（分），寫回 session['wallet_balance_cents']，並回傳整數分。
    """
    try:
        r = (supabase.table('wallet_balances')
             .select('balance_cents')
             .eq('member_id', member_id)
             .single()
             .execute())
        bal = int((r.data or {}).get('balance_cents') or 0)
    except Exception:
        current_app.logger.exception('[wallet] refresh balance failed')
        bal = 0
    session['wallet_balance_cents'] = bal
    return bal

def _calc_available_wallet_cents(credit_rows):
    today = datetime.utcnow().date()
    total = 0
    for r in (credit_rows or []):
        amt = int(r.get("amount_cents") or 0)
        exp = r.get("expires_at")
        if amt < 0:
            total += amt
        else:
            if not exp:
                total += amt
            else:
                try:
                    d = parser.parse(exp).date()
                    if d >= today:
                        total += amt
                except Exception:
                    total += amt
    # ✅ 不允許小於 0
    return max(total, 0)



# ✅ Supabase 初始化（同時支援 SUPABASE_ANON_KEY / SUPABASE_KEY）
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY") or os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# ===== Banners helpers =====
def get_active_banners():
    """
    從 banners 資料表取出啟用中的輪播，依 sort_order 正序。
    """
    try:
        res = (supabase.table("banners")
               .select("*")
               .eq("is_active", True)
               .order("sort_order", desc=False)
               .order("id", desc=False)
               .execute())
        return res.data or []
    except Exception:
        return []


# ✅ 郵件設定
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'hersetbeauty@gmail.com'
app.config['MAIL_PASSWORD'] = 'xlwn swew zqkk fdkt'
app.config['MAIL_DEFAULT_SENDER'] = 'hersetbeauty@gmail.com'
mail = Mail(app)

# === OAuth 設定 ===
APP_ENV = os.getenv("APP_ENV", "production")
OAUTH_REDIRECT_BASE = os.getenv(
    "OAUTH_REDIRECT_BASE",
    "https://herset.co" if APP_ENV == "production" else "http://127.0.0.1:5000"
)

oauth = OAuth(app)

# Google：OpenID Connect
oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# Facebook：Graph API v20
oauth.register(
    name="facebook",
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    access_token_url="https://graph.facebook.com/v20.0/oauth/access_token",
    authorize_url="https://www.facebook.com/v20.0/dialog/oauth",
    api_base_url="https://graph.facebook.com/v20.0/",
    client_kwargs={"scope": "public_profile email"},
)
# Line 〔取代整段註冊，不用 OIDC metadata，避免 Authlib 解析 id_token〕
oauth.register(
    name="line",
    client_id=os.environ["LINE_CHANNEL_ID"],
    client_secret=os.environ["LINE_CHANNEL_SECRET"],
    authorize_url="https://access.line.me/oauth2/v2.1/authorize",
    access_token_url="https://api.line.me/oauth2/v2.1/token",
    api_base_url="https://api.line.me/",
    client_kwargs={
        # 若你沒申請到 email，拿掉 email，保守用 profile 即可；要 email 也可保留
        "scope": "profile",   # 或 "profile openid email"；但不使用 metadata 就不會自動驗 id_token
        "token_endpoint_auth_method": "client_secret_post",
    },
)

OFFICIAL_HOST = "herset.co"

EXEMPT_PREFIXES = (
    "/login/google",   # 包含 /login/google 以及 /login/google/callback
    "/login/facebook", # 包含 /login/facebook 以及 /login/facebook/callback
    "/login/line",     # 包含 /login/line 以及 /login/line/callback
)


@app.before_request
def _force_official_domain():
    p = request.path or ""
    if p.startswith(EXEMPT_PREFIXES):
        return None

    host = (request.host or "").split(":")[0]
    if host and host != OFFICIAL_HOST:
        return redirect(f"https://{OFFICIAL_HOST}{request.full_path}", code=301)

    if not request.is_secure:
        return redirect(f"https://{OFFICIAL_HOST}{request.full_path}", code=301)

    return None


@app.template_filter('nl2br')
def nl2br_filter(s):
    if s is None:
        return ''
    return Markup(s.replace('\n', '<br>\n'))

@app.route('/')
def index():
    category = request.args.get('category')

    # 先抓全部商品
    res = supabase.table("products").select("*").execute()
    products = res.data or []

        # 🔻 過濾：前台只顯示未下架的商品
    products = [p for p in products if not (p.get('is_hidden') is True)]

    # 撈出所有套組，做 (shell_product_id -> bundle資料) 對照
    bres = supabase.table("bundles") \
        .select("id, price, compare_at, shell_product_id") \
        .execute()
    bundles = bres.data or []
    shell_to_bundle = {b["shell_product_id"]: b for b in bundles if b.get("shell_product_id")}

    # 把套組價資訊加到對應殼商品上，給前端好判斷
    for p in products:
        if p.get("product_type") == "bundle":
            b = shell_to_bundle.get(p.get("id"))
            if b:
                p["bundle_price"] = b.get("price")          # 現價
                p["bundle_compare"] = b.get("compare_at")   # 原價(用來算折數)

    # 分類篩選（若有帶 category）
    if category and category != '全部':
        products = [p for p in products if category in (p.get('categories') or [])]

        # ✅ 排序：有「主打商品」tag 的商品排在最前面（其餘維持原本順序）
    for idx, p in enumerate(products):
        p["_orig_idx"] = idx  # 記住原本順序，做穩定排序用

    def is_featured(prod):
        return "主打商品" in (prod.get("tags") or [])

    products.sort(key=lambda p: (0 if is_featured(p) else 1, p.get("_orig_idx", 0)))

    # 清掉暫存欄位，避免影響前端或存回資料庫
    for p in products:
        p.pop("_orig_idx", None)

    cart = session.get('cart', [])
    cart_count = sum(item.get('qty', 0) for item in cart)
    return render_template("index.html", products=products, cart_count=cart_count, banners=get_active_banners())


# ✅ SEO相關
@app.route('/robots.txt')
def robots():
    return send_from_directory('.', 'robots.txt')

@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory('.', 'sitemap.xml')

@app.route('/googlee43955748321cd00.html')
def google_verify():
    return send_from_directory('.', 'googlee43955748321cd00.html')

# logo路由
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

# ✅ 忘記密碼 - 輸入電話與信箱
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        # 僅根據 email 查詢
        res = supabase.table("members").select("*").eq("email", email).execute()
        if res.data:
            code = str(uuid.uuid4())[:6].upper()
            session['reset_code'] = code
            session['reset_user'] = res.data[0]
            try:
                msg = Message("HERSET 驗證碼", recipients=[email])
                msg.body = f"您的驗證碼是：{code}"
                mail.send(msg)
                flash("驗證碼已發送至您的信箱。", "success")
                return redirect("/verify")
            except Exception as e:
                flash("郵件發送失敗: " + str(e), "danger")
        else:
            flash("找不到符合的帳號資訊。", "danger")
    return render_template("forgot.html")

# 按Herset回到首頁
@app.context_processor
def inject_cart_count():
    cart = session.get('cart', [])
    cart_count = sum(item.get('qty', 0) for item in cart)
    return dict(cart_count=cart_count)

# ✅ 設定你自己的帳號密碼(admin login)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "show0363"  # 


# ✅ 刪除訂單密碼驗證路由
@app.route('/admin0363/orders/verify_delete', methods=['POST'])
def verify_admin_for_delete():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return jsonify(success=True)
    else:
        return jsonify(success=False)



@app.route("/admin0363", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True

            # 登入當下抓出目前所有訂單和留言（用來初始 seen 狀態）
            orders = supabase.table("orders").select("status").execute().data or []
            messages = supabase.table("messages").select("is_replied").execute().data or []

            # 如果登入當下就有未出貨訂單 → 不設為已讀，讓警示跳出
            has_unshipped_order = any(o["status"] != "shipped" for o in orders)
            session["seen_orders"] = not has_unshipped_order

            # 如果登入當下就有未回覆留言 → 不設為已讀，讓警示跳出
            has_unreplied_message = any(not m["is_replied"] for m in messages)
            session["seen_messages"] = not has_unreplied_message

            return redirect("/admin0363/dashboard")
        else:
            return render_template("admin_login.html", error="帳號或密碼錯誤")
        # GET：顯示登入頁，同時提示是否有新/未出貨訂單
    try:
        res = (
            supabase.table("orders")
            .select("id", count="exact")
            .in_("status", ["pending", "paid"])   # 只算新訂單/已付款未出貨
            .execute()
        )
        new_order_count = getattr(res, "count", 0) or 0
        new_order_alert = new_order_count > 0
    except Exception:
        new_order_alert = False
        new_order_count = 0

    return render_template(
        "admin_login.html",
        new_order_alert=new_order_alert,
        new_order_count=new_order_count
    )


# admin 後台
@app.route("/admin0363/dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    from pytz import timezone
    from dateutil import parser
    import json

    tz = timezone("Asia/Taipei")
    tab = request.args.get("tab", "products")
    selected_categories = request.args.getlist("category[]")

    # === 商品：搜尋 + 分頁 ===
    product_keyword = request.args.get("product_keyword", "").lower()
    product_page = int(request.args.get("page", 1))
    product_page_size = int(request.args.get("page_size", 10))
    product_start = (product_page - 1) * product_page_size
    product_end = product_start + product_page_size

    product_query = supabase.table("products").select("*")
    if selected_categories:
        filters = [f"categories.cs.{json.dumps([cat])}" for cat in selected_categories]
        product_query = product_query.or_(",".join(filters))

    all_products = product_query.execute().data or []
    if product_keyword:
        all_products = [p for p in all_products if product_keyword in (p.get("name") or "").lower()]

    # 分類數量與合計
    category_counts = {}
    for p in all_products:
        for c in (p.get("categories") or []):
            category_counts[c] = category_counts.get(c, 0) + 1

    if selected_categories:
        selected_category_counts = {c: category_counts.get(c, 0) for c in selected_categories}
        product_total_count = len(all_products)
    else:
        selected_category_counts = {}
        product_total_count = len(all_products)

    product_total_pages = max(1, (product_total_count + product_page_size - 1) // product_page_size)
    products = all_products[product_start:product_end]

    # 取得所有 bundles 的對照，回填到 products
    bundle_map_rows = supabase.table("bundles").select("id, shell_product_id").execute().data or []
    shell_to_bundle = {b["shell_product_id"]: b["id"] for b in bundle_map_rows if b.get("shell_product_id")}
    for p in products:
        if p.get("product_type") == "bundle":
            p["bundle_id"] = shell_to_bundle.get(p.get("id"))

    # === 會員 ===
    members = (supabase.table("members")
           .select("id, account, username, name, phone, email, address, note, created_at, oauth_provider")
           .order("created_at", desc=True)
           .execute().data) or []

    member_total_count = len(members)
    for m in members:
        try:
            if m.get("created_at"):
                utc_dt = parser.parse(m["created_at"])
                m["created_at"] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            m["created_at"] = m.get("created_at", "—")

    member_keyword = request.args.get("member_keyword", "").lower()
    if member_keyword:
        members = [
            m for m in members
            if member_keyword in (m.get("account") or "").lower()
            or member_keyword in (m.get("name") or "").lower()
            or member_keyword in (m.get("username") or "").lower()
            or member_keyword in (m.get("phone") or "").lower()
            or member_keyword in (m.get("email") or "").lower()
        ]

    # 會員分頁（固定在 if 外）
    member_page = int(request.args.get("member_page", 1))
    member_page_size = int(request.args.get("member_page_size", 5))
    member_total_count_filtered = len(members)
    member_total_pages = max(1, (member_total_count_filtered + member_page_size - 1) // member_page_size)
    member_start = (member_page - 1) * member_page_size
    member_end = member_start + member_page_size
    members = members[member_start:member_end]

    # === 訂單 ===
    order_page = int(request.args.get("order_page", 1))
    order_page_size = int(request.args.get("order_page_size", 20))
    order_start = (order_page - 1) * order_page_size
    order_end = order_start + order_page_size - 1

    order_total_res = supabase.table("orders").select("id", count="exact").execute()
    order_total_count = order_total_res.count or 0

    orders_raw = (supabase.table("orders")
                  .select("*")
                  .order("created_at", desc=True)
                  .range(order_start, order_end)
                  .execute().data or [])

    order_ids = [o["id"] for o in orders_raw]
    member_ids = list({o["member_id"] for o in orders_raw if o.get("member_id")})

     # === 新增：一次撈出每張訂單使用的購物金（單位：分 / cents）===
    wallet_used_map = {}
    if order_ids:
        wc_rows = (
            supabase.table("wallet_credits")
            .select("related_order_id, amount_cents")
            .in_("related_order_id", order_ids)
            .execute()
            .data
            or []
        )
        for r in wc_rows:
            oid = r.get("related_order_id")
            if not oid:
                continue
            amt = int(r.get("amount_cents") or 0)
            cur = wallet_used_map.get(oid, 0)
            if amt < 0:
                # 使用購物金（負數）→ 累加絕對值
                cur += (-amt)
            else:
                # 退回購物金（正數）→ 扣回
                cur -= amt
            wallet_used_map[oid] = max(0, cur)

    order_items = supabase.table("order_items").select("*").in_("order_id", order_ids).execute().data or []
    members_res = supabase.table("members").select("id, account, name, phone, address").in_("id", member_ids).execute().data or []
    member_dict = {m["id"]: m for m in members_res}

    item_group = {}
    for item in order_items:
        item_group.setdefault(item["order_id"], []).append({
            "product_name": item.get("product_name"),
            "qty": item.get("qty"),
            "price": item.get("price"),
            "option": item.get("option", "")
        })

    orders = []
    for o in orders_raw:
        o["items"] = item_group.get(o["id"], [])
        member = member_dict.get(o["member_id"])
        o["member"] = {
            "account": member["account"] if member else "guest",
            "name": member.get("name") if member else "訪客",
            "phone": member.get("phone") if member else "—",
            "address": member.get("address") if member else "—",
        }
        o["is_new"] = bool(o.get("status") != "shipped" and not session.get("seen_orders"))
        try:
            utc_dt = parser.parse(o["created_at"])
            o["created_local"] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            o["created_local"] = o["created_at"]

        # ★★★ 新增這兩行：把「本張訂單使用的購物金」帶到模板 ★★★
        o["wallet_used_cents"] = int(wallet_used_map.get(o["id"], 0))
        o["wallet_used_nt"]    = o["wallet_used_cents"] // 100

        orders.append(o)
    unshipped_count = sum(1 for o in orders if (o.get("status") in (None, "pending", "paid")))

    # === 留言 + 分頁 ===
    reply_status = request.args.get("reply_status", "all")
    msg_type = request.args.get("type", "")
    msg_keyword = request.args.get("keyword", "").lower()
    msg_page = int(request.args.get("msg_page", 1))
    msg_page_size = int(request.args.get("msg_page_size", 10))

    all_messages = (supabase.table("messages")
                    .select("*")
                    .order("created_at", desc=True)
                    .execute().data or [])

    member_ids2 = list({m['member_id'] for m in all_messages})
    name_map = {}
    if member_ids2:
        members_res2 = supabase.table("members").select("id, name").in_("id", member_ids2).execute().data or []
        name_map = {m['id']: m['name'] for m in members_res2}

    for m in all_messages:
        m["member_name"] = name_map.get(m.get("member_id"), "未知")
        m["is_new"] = bool(not m.get("is_replied") and not session.get("seen_messages"))
        try:
            utc_dt = parser.parse(m["created_at"])
            m["local_created_at"] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M")
        except Exception:
            m["local_created_at"] = m["created_at"]
    unreplied_count = sum(1 for m in all_messages if not m.get("is_replied"))

    filtered_messages = []
    for m in all_messages:
        match_status = (
            reply_status == "all" or
            (reply_status == "replied" and m.get("is_replied")) or
            (reply_status == "unreplied" and not m.get("is_replied"))
        )
        match_type = (not msg_type) or (m.get("type") == msg_type)
        match_name = (not msg_keyword) or (msg_keyword in (m.get("member_name") or "").lower())
        if match_status and match_type and match_name:
            filtered_messages.append(m)

    msg_total_count = len(filtered_messages)
    msg_total_pages = max(1, (msg_total_count + msg_page_size - 1) // msg_page_size)
    msg_start = (msg_page - 1) * msg_page_size
    msg_end = msg_start + msg_page_size
    paged_messages = filtered_messages[msg_start:msg_end]

    # === 提示狀態 ===
    new_order_alert = any(o.get("status") in ("pending", "paid") for o in orders)
    new_message_alert = any(not m.get("is_replied") for m in all_messages)
    show_order_alert = new_order_alert and not session.get("seen_orders")
    show_message_alert = new_message_alert and not session.get("seen_messages")

    # === 供「發送訊息」表單使用的會員下拉 ===
    member_options = []
    if tab == "messages":
        try:
            member_options = (supabase.table("members")
                              .select("id, name, account, email")
                              .order("created_at", desc=True)
                              .limit(5000)
                              .execute().data) or []
        except Exception:
            member_options = []

    # === Render ===
    question_types = ["商品問題", "訂單問題", "其他"]
    response = render_template(
        "admin.html",
        tab=tab,
        selected_categories=selected_categories,
        products=products,
        product_page=product_page,
        product_total_pages=product_total_pages,
        product_page_size=product_page_size,
        members=members,
        member_total_count=member_total_count,
        orders=orders,
        messages=paged_messages,
        new_order_alert=show_order_alert,
        new_message_alert=show_message_alert,
        msg_page=msg_page,
        msg_total_pages=msg_total_pages,
        order_page=order_page,
        order_total_count=order_total_count,
        question_types=question_types,
        # 顯示用統計
        product_total_count=product_total_count,
        selected_category_counts=selected_category_counts,
        category_counts=category_counts,
        unshipped_count=unshipped_count,
        unreplied_count=unreplied_count,
        # 會員分頁用
        member_page=member_page,
        member_total_pages=member_total_pages,
        member_page_size=member_page_size,
        member_options=member_options,

    )

    # 進此頁後視為已讀
    session["seen_orders"] = True
    session["seen_messages"] = True
    return response


# ================================
#  後台：新增套組（顯示頁）
#  URL: GET /admin0363/bundles/new
# ================================
@app.route("/admin0363/bundles/new", methods=["GET"])
def admin_new_bundle():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    # ---- GET：渲染表單 ----
    # 只抓單品當可選池
    products = (
        supabase.table("products")
        .select("id,name,price,product_type,options")
        .eq("product_type", "single")
        .order("name")
        .execute()
        .data
        or []
    )

    # 彙整全站分類/標籤供下拉選
    vocab_rows = supabase.table("products").select("categories,tags").execute().data or []
    cat_set, tag_set = set(), set()
    for r in vocab_rows:
        for c in (r.get("categories") or []):
            if c:
                cat_set.add(c)
        for t in (r.get("tags") or []):
            if t:
                tag_set.add(t)

    all_categories = sorted({*cat_set, "套組優惠"})
    all_tags = sorted(tag_set)

    # 空的 bundle（模板會用到）
    empty_bundle = {
        "name": "",
        "price": None,
        "compare_at": None,
        "stock": 0,
        "description": "",
        "intro": "",
        "feature": "",
        "spec": "",
        "categories": ["套組優惠"],
        "tags": [],
        "required_total": 0,
        "cover_image": None,
        "is_hidden": False,
    }

    return render_template(
        "new_bundle.html",
        products=products,
        all_categories=all_categories,
        all_tags=all_tags,
        bundle=empty_bundle,
    )


# ================================
#  後台：新增套組（儲存）
#  URL: POST /admin0363/bundles/new
# ================================
@app.route("/admin0363/bundles/new", methods=["POST"])
def admin_create_bundle():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    form = request.form
    name    = (form.get("name") or "").strip()
    intro   = (form.get("intro") or "").strip()     # 🔸商品介紹（RTE）
    feature = (form.get("feature") or "").strip()   # 🔸商品特色（RTE）
    spec    = (form.get("spec") or "").strip()      # 🔸商品規格描述（RTE）

    # 數值容錯
    def _to_float(v, default=None):
        try:
            s = (v or "").strip().replace(",", "")
            if s == "": return default
            return float(s)
        except Exception:
            return default
    def _to_int(v, default=0):
        try:
            return int((v or "0").strip())
        except Exception:
            return default

    price          = _to_float(form.get("price"), 0.0)
    compare_at     = _to_float(form.get("compare_at"), None)
    stock          = _to_int(form.get("stock"), 0)
    description    = (form.get("description") or "").strip()  # 後台備註（只進 bundles）
    required_total = _to_int(form.get("required_total"), 0)
    is_hidden = bool(form.get("is_hidden"))  # ← 新增：是否下架

    # 共用可選池 / 動態 slots
    pool_ids    = [pid for pid in request.form.getlist("pool_ids[]") if pid]
    slot_labels = request.form.getlist("slot_label[]")
    slot_counts = request.form.getlist("slot_required[]")

    # 分類/標籤
    sel_cats = form.getlist("categories[]")
    new_cats = [s.strip() for s in (form.get("new_categories") or "").split(",") if s.strip()]
    final_categories = list(dict.fromkeys(["套組優惠"] + sel_cats + new_cats))

    sel_tags = form.getlist("tags[]")
    new_tags = [s.strip() for s in (form.get("new_tags") or "").split(",") if s.strip()]
    final_tags = list(dict.fromkeys(sel_tags + new_tags))

    # 封面圖（上傳至 images bucket 的 bundle_images/）
    cover_image_url = None
    cover_image_file = request.files.get("cover_image")
    if cover_image_file and cover_image_file.filename:
        filename = secure_filename(cover_image_file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        storage_path = f"bundle_images/{unique_filename}"
        tmp_path = None
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cover_image_file.save(tmp.name); tmp_path = tmp.name
        try:
            supabase.storage.from_("images").upload(storage_path, tmp_path)
            cover_image_url = supabase.storage.from_("images").get_public_url(storage_path)
        except Exception as e:
            print("❗️套組封面上傳錯誤：", e)
        finally:
            if tmp_path:
                try: os.unlink(tmp_path)
                except: pass

    # ✅ 新增哪一段：影片處理（表單連結 + 上傳檔）
    # 表單貼的影片連結
    video_urls_from_form = [
        (u or "").strip()
        for u in request.form.getlist("video_urls[]")
        if (u or "").strip()
    ]
    # 上傳的影片檔（放到 images bucket 的 bundle_videos/）
    allowed_video_ext = {"mp4", "webm", "ogv", "mov", "m4v"}
    video_urls_from_upload = []
    for vf in request.files.getlist("video_files"):
        if not vf or not vf.filename: continue
        ext = (vf.filename.rsplit(".", 1)[-1] or "").lower()
        if ext not in allowed_video_ext:
            print(f"⚠️ 略過不支援的影片格式：{vf.filename}")
            continue
        v_name = secure_filename(vf.filename)
        v_unique = f"{uuid.uuid4()}_{v_name}"
        v_path = f"bundle_videos/{v_unique}"
        tmp_path = None
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            vf.save(tmp.name); tmp_path = tmp.name
        try:
            supabase.storage.from_("images").upload(v_path, tmp_path)
            v_url = supabase.storage.from_("images").get_public_url(v_path)
            video_urls_from_upload.append(v_url)
        except Exception as e:
            print("❗️影片上傳錯誤：", e)
        finally:
            if tmp_path:
                try: os.unlink(tmp_path)
                except: pass

    videos = video_urls_from_upload + video_urls_from_form  # ← 合併

    # 1) 建立 bundles 主檔（🔸這裡「取代」你原本 insert 的 dict，加入 videos）
    inserted = (
        supabase.table("bundles")
        .insert({
            "name": name,
            "price": price,
            "compare_at": compare_at,
            "stock": stock,
            "cover_image": cover_image_url,
            "description": description,   # 只放 bundles
            "active": True,
            "required_total": required_total,
            "categories": final_categories,
            "tags": final_tags,
            "videos": videos,             # ✅ 新增：套組影片
            "is_hidden": is_hidden,          # ★ 新增：套組下架旗標
        })
        .execute()
        .data
    )
    bundle_id = inserted[0]["id"]

    # 2) slots + slot_pool（維持原本）
    for idx, label in enumerate(slot_labels):
        cnt = _to_int(slot_counts[idx] if idx < len(slot_counts) else 1, 1)
        ins = (
            supabase.table("bundle_slots")
            .insert({
                "bundle_id": bundle_id,
                "slot_index": idx,
                "slot_label": (label or f"選擇{idx+1}").strip(),
                "required_count": cnt
            })
            .execute()
            .data
        )
        slot_id = ins[0]["id"]

        slot_pool_ids = [pid for pid in request.form.getlist(f"slot_pool_{idx}[]") if pid]
        for pid in slot_pool_ids:
            try:
                supabase.table("bundle_slot_pool").insert({
                    "bundle_id": bundle_id,
                    "slot_id": slot_id,
                    "product_id": int(pid)
                }).execute()
            except Exception as e:
                print("❗️寫入 bundle_slot_pool 失敗：", idx, pid, e)

    # 3) 共用可選池（維持原本）
    for pid in pool_ids:
        try:
            supabase.table("bundle_pool").insert({
                "bundle_id": bundle_id,
                "product_id": int(pid)
            }).execute()
        except Exception as e:
            print("❗️寫入 bundle_pool 失敗：", pid, e)

    # 4) 建立殼商品（🔴 intro/feature/spec 來自表單；✅ 同步寫入 products.videos）
    try:
        shell_insert = (
            supabase.table("products")
            .insert({
                "name": f"[套組優惠] {name}",
                "price": price,
                "discount_price": None,
                "stock": stock,
                "image": (cover_image_url or DEFAULT_SHELL_IMAGE),
                "images": [],
                "intro": intro,
                "feature": feature,
                "spec": spec,
                "ingredient": "",
                "options": [],
                "categories": final_categories,
                "tags": final_tags,
                "product_type": "bundle",
                "videos": videos,  # ✅ 殼商品也存影片，商品頁相簿可直接顯示
                "is_hidden": is_hidden,       # ★ 新增：殼商品同樣下架
            })
            .execute()
        )
        shell_product_id = shell_insert.data[0]["id"]
        supabase.table("bundles").update({
            "shell_product_id": shell_product_id
        }).eq("id", bundle_id).execute()
    except Exception as e:
        print("❗️建立套組殼品項或回寫失敗：", e)

    flash("已建立新的套組", "success")
    return redirect("/admin0363/dashboard?tab=products")



# ================================
#  後台：編輯套組（顯示頁）
#  URL: GET /admin0363/bundles/<int:bundle_id>/edit
# ================================
@app.route("/admin0363/bundles/<int:bundle_id>/edit", methods=["GET"])
def admin_edit_bundle(bundle_id):
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    # 讀套組主檔（用 limit(1) 避免 .single() 在 0 筆時丟錯）
    bres = (
        supabase.table("bundles")
        .select("*")
        .eq("id", bundle_id)
        .limit(1)
        .execute()
    )
    b = (bres.data or [None])[0]
    if not b:
        return "找不到套組", 404

    # ---- 取得全站的分類/標籤供下拉選（從 products 彙整）----
    vocab_rows = supabase.table("products").select("categories,tags").execute().data or []
    cat_set, tag_set = set(), set()
    for r in vocab_rows:
        for c in (r.get("categories") or []):
            if c: cat_set.add(c)
        for t in (r.get("tags") or []):
            if t: tag_set.add(t)

    # ---- 從殼商品讀 intro/feature/spec 與可能的分類/標籤 ----
    sp = {}
    shell_id = b.get("shell_product_id")
    if shell_id:
        spres = (
            supabase.table("products")
            .select("intro,feature,spec,categories,tags")
            .eq("id", shell_id)
            .limit(1)
            .execute()
        )
        sp = (spres.data or [None])[0] or {}

    # 分類/標籤：以 bundles 為主，沒有才回退殼商品
    cats = b.get("categories")
    if not isinstance(cats, list): cats = []
    if not cats: cats = sp.get("categories") or []

    tags = b.get("tags")
    if not isinstance(tags, list): tags = []
    if not tags: tags = sp.get("tags") or []

    # 編輯頁需要的文字欄位：優先用殼商品，沒有再給空字串
    b["intro"] = sp.get("intro") or b.get("intro") or ""
    b["feature"] = sp.get("feature") or b.get("feature") or ""
    b["spec"] = sp.get("spec") or b.get("spec") or ""
    b["categories"] = cats
    b["tags"] = tags

    # 全部可選清單：包含站內蒐集 + 目前已選
    all_categories = sorted({*cat_set, *cats, "套組優惠"})
    all_tags = sorted({*tag_set, *tags})

    # ---- slots ----
    slots = (
        supabase.table("bundle_slots")
        .select("*")
        .eq("bundle_id", bundle_id)
        .order("slot_index")
        .execute()
        .data
        or []
    )

    # ---- 共用可選池（bundle_pool）----
    pool_rows = (
        supabase.table("bundle_pool")
        .select("product_id")
        .eq("bundle_id", bundle_id)
        .execute()
        .data
        or []
    )
    pool_ids = [r["product_id"] for r in pool_rows]

    # ---- 各欄位限定可選商品（bundle_slot_pool）→ {slot_id: [product_id,...]} ----
    slot_pool_rows = (
        supabase.table("bundle_slot_pool")
        .select("slot_id, product_id")
        .eq("bundle_id", bundle_id)
        .execute()
        .data
        or []
    )
    slot_pool_map = {}
    for r in slot_pool_rows:
        slot_pool_map.setdefault(r["slot_id"], []).append(r["product_id"])

    # ---- 後台可選的單品清單（下拉）----
    all_single_products = (
        supabase.table("products")
        .select("id,name,price,product_type")
        .eq("product_type", "single")
        .eq("is_hidden", False)   # ← 可選：後台挑選來源也排除下架單品
        .order("name")
        .execute()
        .data
        or []
    )

    return render_template(
        "edit_bundle.html",
        bundle=b,
        slots=slots,
        pool_ids=pool_ids,
        products=all_single_products,
        slot_pool_map=slot_pool_map,
        all_categories=all_categories,
        all_tags=all_tags,
    )




# ================================
#  後台：編輯套組（儲存）
#  URL: POST /admin0363/bundles/<int:bundle_id>/edit
# ================================
@app.route("/admin0363/bundles/<int:bundle_id>/edit", methods=["POST"])
def admin_update_bundle(bundle_id):
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    form = request.form
    def _to_float(v, default=None):
        try:
            s = (v or "").strip().replace(",", "")
            if s == "": return default
            return float(s)
        except Exception: return default
    def _to_int(v, default=0):
        try: return int((v or "0").strip())
        except Exception: return default

    name           = (form.get("name") or "").strip()
    price          = _to_float(form.get("price"), 0.0)
    compare_at     = _to_float(form.get("compare_at"), None)
    stock          = _to_int(form.get("stock"), 0)
    description    = (form.get("description") or "").strip()
    required_total = _to_int(form.get("required_total"), 0)
    intro          = (form.get("intro") or "").strip()
    feature        = (form.get("feature") or "").strip()
    spec           = (form.get("spec") or "").strip()

    # ✅ 新增：讀取是否下架
    is_hidden = bool(form.get("is_hidden"))

    # 共用可選池 / 動態 slots / 分類標籤（維持你原本）
    pool_ids    = [pid for pid in request.form.getlist("pool_ids[]") if pid]
    slot_labels = request.form.getlist("slot_label[]")
    slot_counts = request.form.getlist("slot_required[]")
    sel_cats = form.getlist("categories[]")
    new_cats = [s.strip() for s in (form.get("new_categories") or "").split(",") if s.strip()]
    final_categories = list(dict.fromkeys(["套組優惠"] + sel_cats + new_cats))
    sel_tags = form.getlist("tags[]")
    new_tags = [s.strip() for s in (form.get("new_tags") or "").split(",") if s.strip()]
    final_tags = list(dict.fromkeys(sel_tags + new_tags))

    # 封面圖
    cover_image_url = None
    cover_image_file = request.files.get("cover_image")
    if cover_image_file and cover_image_file.filename:
        filename = secure_filename(cover_image_file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        storage_path = f"bundle_images/{unique_filename}"
        tmp_path = None
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cover_image_file.save(tmp.name); tmp_path = tmp.name
        try:
            supabase.storage.from_("images").upload(storage_path, tmp_path)
            cover_image_url = supabase.storage.from_("images").get_public_url(storage_path)
        except Exception as e:
            print("❗️套組封面上傳錯誤：", e)
        finally:
            if tmp_path:
                try: os.unlink(tmp_path)
                except: pass

    # 影片處理（保留舊 + 新增連結 + 新上傳）
    kept_videos = request.form.getlist("existing_videos[]")
    video_urls_from_form = [
        (u or "").strip()
        for u in request.form.getlist("video_urls[]")
        if (u or "").strip()
    ]
    allowed_video_ext = {"mp4", "webm", "ogv", "mov", "m4v"}
    video_urls_from_upload = []
    for vf in request.files.getlist("video_files"):
        if not vf or not vf.filename: continue
        ext = (vf.filename.rsplit(".", 1)[-1] or "").lower()
        if ext not in allowed_video_ext:
            print(f"⚠️ 略過不支援的影片格式：{vf.filename}")
            continue
        v_name = secure_filename(vf.filename)
        v_unique = f"{uuid.uuid4()}_{v_name}"
        v_path = f"bundle_videos/{v_unique}"
        tmp_path = None
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            vf.save(tmp.name); tmp_path = tmp.name
        try:
            supabase.storage.from_("images").upload(v_path, tmp_path)
            v_url = supabase.storage.from_("images").get_public_url(v_path)
            video_urls_from_upload.append(v_url)
        except Exception as e:
            print("❗️影片上傳錯誤：", e)
        finally:
            if tmp_path:
                try: os.unlink(tmp_path)
                except: pass

    videos = kept_videos + video_urls_from_form + video_urls_from_upload

    # 1) 更新 bundles 主檔 —— ✅ 修改：加入 is_hidden
    update_data = {
        "name": name,
        "price": price,
        "compare_at": compare_at,
        "stock": stock,
        "description": description,
        "required_total": required_total,
        "categories": final_categories,
        "tags": final_tags,
        "videos": videos,
        "is_hidden": is_hidden,  # ★ 新增
    }
    if cover_image_url:
        update_data["cover_image"] = cover_image_url
    supabase.table("bundles").update(update_data).eq("id", bundle_id).execute()

    # 2) 重建 slots / slot_pool（維持你原本）
    supabase.table("bundle_slots").delete().eq("bundle_id", bundle_id).execute()
    supabase.table("bundle_slot_pool").delete().eq("bundle_id", bundle_id).execute()
    for idx, label in enumerate(slot_labels):
        cnt = _to_int(slot_counts[idx] if idx < len(slot_counts) else 1, 1)
        ins = (supabase.table("bundle_slots").insert({
            "bundle_id": bundle_id,
            "slot_index": idx,
            "slot_label": (label or f"選擇{idx+1}").strip(),
            "required_count": cnt
        }).execute().data)
        slot_id = ins[0]["id"]
        slot_pool_ids = [pid for pid in request.form.getlist(f"slot_pool_{idx}[]") if pid]
        for pid in slot_pool_ids:
            try:
                supabase.table("bundle_slot_pool").insert({
                    "bundle_id": bundle_id,
                    "slot_id": slot_id,
                    "product_id": int(pid)
                }).execute()
            except Exception as e:
                print("❗️寫入 bundle_slot_pool 失敗：", idx, pid, e)

    # 3) 共用可選池（維持你原本）
    supabase.table("bundle_pool").delete().eq("bundle_id", bundle_id).execute()
    for pid in pool_ids:
        try:
            supabase.table("bundle_pool").insert({
                "bundle_id": bundle_id,
                "product_id": int(pid)
            }).execute()
        except Exception as e:
            print("❗️寫入 bundle_pool 失敗：", pid, e)

    # 4) 同步殼商品（intro/feature/spec/封面 & 影片）—— ✅ 修改：同步 is_hidden
    bres = (
        supabase.table("bundles")
        .select("shell_product_id, cover_image")
        .eq("id", bundle_id).limit(1).execute()
    )
    bundle_row = (bres.data or [None])[0] or {}
    shell_id = bundle_row.get("shell_product_id")
    current_cover = cover_image_url or bundle_row.get("cover_image") or DEFAULT_SHELL_IMAGE

    if not shell_id:
        # 沒殼就補建 —— ✅ 新增 is_hidden
        try:
            shell_insert = (
                supabase.table("products")
                .insert({
                    "name": f"[套組優惠] {name}",
                    "price": price,
                    "discount_price": None,
                    "stock": stock,
                    "image": (current_cover or DEFAULT_SHELL_IMAGE),
                    "images": [],
                    "intro": intro,
                    "feature": feature,
                    "spec": spec,
                    "ingredient": "",
                    "options": [],
                    "categories": final_categories,
                    "tags": final_tags,
                    "product_type": "bundle",
                    "videos": videos,
                    "is_hidden": is_hidden,  # ★ 新增
                })
                .execute()
            )
            shell_id = shell_insert.data[0]["id"]
            supabase.table("bundles").update({"shell_product_id": shell_id}).eq("id", bundle_id).execute()
        except Exception as e:
            print("❗️建立套組殼品項失敗：", e)
    else:
        # 更新既有殼商品 —— ✅ 新增 is_hidden
        shell_update = {
            "name": f"[套組優惠] {name}",
            "price": price,
            "stock": stock,
            "intro": intro,
            "feature": feature,
            "spec": spec,
            "categories": final_categories,
            "tags": final_tags,
            "videos": videos,
            "is_hidden": is_hidden,  # ★ 新增
        }
        if current_cover:
            shell_update["image"] = current_cover
        try:
            supabase.table("products").update(shell_update).eq("id", shell_id).execute()
        except Exception as e:
            print("❗️更新套組殼品項失敗：", e)

    flash("套組已更新", "success")
    return redirect("/admin0363/dashboard?tab=products")






# ✅ TinyMCE 圖片上傳端點
@app.route('/admin0363/tinymce/upload', methods=['POST'])
def tinymce_upload():
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'no file'}), 400

    # 允許的副檔名
    allowed = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    ext = (file.filename.rsplit('.', 1)[-1] or '').lower()
    if ext not in allowed:
        return jsonify({'error': 'invalid type'}), 400

    # 目錄：static/uploads/rte
    save_dir = os.path.join(app.root_path, 'static', 'uploads', 'rte')
    os.makedirs(save_dir, exist_ok=True)

    # 產生安全且唯一的檔名
    filename = secure_filename(file.filename)
    filename = f"{uuid.uuid4().hex}.{ext}"
    save_path = os.path.join(save_dir, filename)

    # 寫檔
    file.save(save_path)

    # 回傳可直接使用的網址給 TinyMCE
    url = url_for('static', filename=f'uploads/rte/{filename}')
    return jsonify({'location': url})

#admin 功能管理標籤 功能管理中樞頁（Hub）

@app.route("/admin0363/features")
def admin_features_hub():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")
    # 中樞頁不需要 discounts 參數
    return render_template("features_hub.html")

# ====== Admin: 首頁輪播圖管理開始 ======
from werkzeug.utils import secure_filename
import os, time, json

# 本地上傳目錄（會自動建立）
BANNER_UPLOAD_DIR = os.path.join(app.root_path, "static", "uploads", "banners")
os.makedirs(BANNER_UPLOAD_DIR, exist_ok=True)

def _admin_required_redirect():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

@app.get("/admin0363/features/banners")
def admin_banners_page():
    auth = _admin_required_redirect()
    if auth: return auth
    res = supabase.table("banners").select("*").order("sort_order").order("id").execute()
    items = res.data or []
    return render_template("admin_banners.html", items=items)

@app.post("/admin0363/features/banners/upload")
def admin_banners_upload():
    auth = _admin_required_redirect()
    if auth: return auth
    title = (request.form.get("title") or "").strip()
    href  = (request.form.get("href") or "").strip()
    f = request.files.get("image")
    if not f or not f.filename:
        return "缺少圖片", 400

    # 儲存實體檔
    ext = (f.filename.rsplit(".", 1)[-1] or "").lower()
    safe_name = secure_filename(f.filename)
    unique = f"{uuid4()}_{safe_name}"
    storage_path = f"banners/{unique}"

    tmp_path = None
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name
    try:
        supabase.storage.from_("images").upload(storage_path, tmp_path)
    finally:
        if tmp_path:
            try: os.unlink(tmp_path)
            except: pass

    # 取得公開網址（這個網址可跨機、重啟、換節點）
    image_url = supabase.storage.from_("images").get_public_url(storage_path)

    # ➊ 取得目前最大 sort_order，計算下一個號碼（沒有資料時從 0 開始）
    try:
        last = (supabase.table("banners")
                .select("sort_order")
                .order("sort_order", desc=True)
                .limit(1).execute().data)
        cur_max = last[0].get("sort_order") if last else None
        next_order = (int(cur_max) + 1) if isinstance(cur_max, (int, float)) else 0
    except Exception:
        next_order = 0

    # ➋ 帶入 sort_order 寫入
    supabase.table("banners").insert({
        "title": title or None,
        "href": href or None,
        "image_url": image_url,
        "is_active": True,
        "sort_order": next_order,   # ← 新增這行
    }).execute()

    return redirect("/admin0363/features/banners")

@app.post("/admin0363/features/banners/toggle/<int:bid>")
def admin_banners_toggle(bid):
    auth = _admin_required_redirect()
    if auth: return auth
    row = supabase.table("banners").select("is_active").eq("id", bid).limit(1).execute().data
    cur = bool(row and row[0].get("is_active"))
    supabase.table("banners").update({"is_active": not cur}).eq("id", bid).execute()
    return redirect("/admin0363/features/banners")

@app.post("/admin0363/features/banners/delete/<int:bid>")
def admin_banners_delete(bid):
    auth = _admin_required_redirect()
    if auth: return auth
    row = supabase.table("banners").select("image_url").eq("id", bid).limit(1).execute().data
    supabase.table("banners").delete().eq("id", bid).execute()

    if row:
        url = row[0].get("image_url") or ""
        # 1) 若是 Supabase Storage 公開網址（常見長相 .../object/public/images/banners/...）
        if "/object/public/images/" in url:
            # 擷取 object key：images bucket 之後那段，例如 banners/uuid_filename.jpg
            # 公開網址大概像 https://xxxx.supabase.co/storage/v1/object/public/images/banners/xxx.jpg
            key = url.split("/object/public/images/", 1)[-1]  # -> banners/xxx.jpg
            try:
                supabase.storage.from_("images").remove([key])
            except Exception as e:
                print("刪 Storage 檔案失敗：", e)
        # 2) 舊資料：本機檔案路徑才嘗試刪除
        elif url.startswith("/static/uploads/banners/"):
            try:
                os.remove(os.path.join(app.root_path, url.lstrip("/")))
            except Exception:
                pass
    return redirect("/admin0363/features/banners")

@app.post("/admin0363/features/banners/reorder")
def admin_banners_reorder():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    # 1) 先試 JSON: {"ids":[6,7,8,9]}
    data = request.get_json(silent=True) or {}
    ids = data.get("ids")

    # 2) 若沒拿到，再試 form：ids=6,7,8,9
    if not ids:
        raw = (request.form.get("ids") or "").strip()
        if raw:
            ids = [int(x) for x in raw.split(",") if x.strip().isdigit()]

    # 3) 還是沒有 → 回傳錯誤提示（方便除錯）
    if not ids:
        return jsonify(ok=False, error="no ids"), 400

    # 4) 逐筆更新 sort_order
    for idx, bid in enumerate(ids):
        try:
            supabase.table("banners").update({"sort_order": idx}).eq("id", bid).execute()
        except Exception as e:
            print("update sort_order failed:", bid, e)

    return jsonify(ok=True)

@app.post("/admin0363/features/banners/update/<int:bid>")
def admin_banners_update(bid):
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    title = (request.form.get("title") or "").strip()
    href  = (request.form.get("href") or "").strip()

    payload = {
        "title": (title or None),
        "href":  (href or None),
    }
    try:
        supabase.table("banners").update(payload).eq("id", bid).execute()
    except Exception as e:
        print("更新 banner 失敗：", e)

    return redirect("/admin0363/features/banners")



# ====== Admin: 首頁輪播圖管理 結束======

# 功能管理 → 網站綜合設定（表單頁）
@app.get("/admin0363/features/settings")
def admin_features_settings():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")
    threshold, ship_fee = get_shipping_rules()
    return render_template("features_settings.html",
                           free_shipping_threshold=threshold,
                           shipping_fee=ship_fee)


# admin功能管理 → 網站綜合設定（儲存）
@app.post("/admin0363/features/settings")
def admin_features_settings_save():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    # 簡單防呆：負數視為 0
    try:
        threshold = max(0.0, float(request.form.get("free_shipping_threshold") or 0))
    except Exception:
        threshold = 0.0
    try:
        ship_fee = max(0.0, float(request.form.get("shipping_fee") or 0))
    except Exception:
        ship_fee = 0.0

    ok1 = set_setting_num("free_shipping_threshold", threshold)
    ok2 = set_setting_num("shipping_fee", ship_fee)

    if ok1 and ok2:
        flash("網站綜合設定已儲存", "success")
    else:
        flash("儲存失敗，請稍後再試", "error")

    return redirect("/admin0363/features/settings")


# ✅ TinyMCE 影片上傳端點
@app.route('/admin0363/tinymce/upload_video', methods=['POST'])
def tinymce_upload_video():
    if not session.get("admin_logged_in"):
        return jsonify({'error': 'unauthorized'}), 401

    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'error': 'no file'}), 400

    ext = (f.filename.rsplit('.', 1)[-1] or '').lower()
    allowed = {'mp4', 'webm', 'ogv', 'mov', 'm4v'}
    if ext not in allowed:
        return jsonify({'error': 'unsupported'}), 400

    try:
        fname = secure_filename(f.filename)
        unique = f"{uuid.uuid4()}_{fname}"
        storage_path = f"editor_videos/{unique}"  # 建議專用資料夾

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            f.save(tmp.name)
            supabase.storage.from_("images").upload(storage_path, tmp.name)

        url = supabase.storage.from_("images").get_public_url(storage_path)
        return jsonify({'location': url})
    except Exception as e:
        print("❗️TinyMCE 影片上傳錯誤：", e)
        return jsonify({'error': 'upload failed'}), 500


# === 新增折扣碼（表單頁） ===
@app.route("/admin0363/discounts/new")
def admin_discounts_new():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")
    return render_template("discount_new.html")

# === 新增折扣碼（提交） ===
@app.route("/admin0363/discounts/new", methods=["POST"])
def admin_discounts_create():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")
    form = request.form
    payload = {
        "code": (form.get("code") or "").strip().upper(),
        "type": form.get("type") or "amount",
        "value": float(form.get("value") or 0),
        "min_order_amt": float(form.get("min_order_amt") or 0),
        "start_at":   to_utc_iso_from_tw(form.get("start_at")),
        "expires_at": to_utc_iso_from_tw(form.get("expires_at")),
        "usage_limit": int(form.get("usage_limit")) if form.get("usage_limit") else None,
        "per_user_limit": int(form.get("per_user_limit")) if form.get("per_user_limit") else None,
        "is_active": form.get("is_active") == "on",
        "note": form.get("note") or None,
    }
    supabase.table("discounts").insert(payload).execute()
    flash("折扣碼已新增", "success")
    return redirect("/admin0363/features")

# === 刪除折扣碼 ===
@app.route("/admin0363/discounts/delete/<int:did>", methods=["POST"])
def admin_discounts_delete(did):
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")
    supabase.table("discounts").delete().eq("id", did).execute()
    flash("折扣碼已刪除", "success")
    return redirect("/admin0363/features")

# === 折扣碼編輯（表單頁） ===
@app.route("/admin0363/discounts/edit/<int:did>", methods=["GET"])
def admin_discounts_edit(did):
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")
    # 讀取單筆折扣碼
    try:
        res = supabase.table("discounts").select("*").eq("id", did).single().execute()
        d = res.data
        if not d:
            flash("找不到折扣碼", "error")
            return redirect("/admin0363/features")
    except Exception:
        flash("讀取折扣碼失敗", "error")
        return redirect("/admin0363/features")
    return render_template("discount_edit.html", d=d)

# === 折扣碼編輯（提交） ===
@app.route("/admin0363/discounts/edit/<int:did>", methods=["POST"])
def admin_discounts_update(did):
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    form = request.form
    # 基本防呆
    _type = form.get("type") or "amount"
    _value = float(form.get("value") or 0)
    if _type == "percent":
        # 百分比限制 0~100
        _value = max(0.0, min(100.0, _value))

    payload = {
        "code": (form.get("code") or "").strip().upper(),
        "type": _type,
        "value": _value,
        "min_order_amt": float(form.get("min_order_amt") or 0),
        "start_at":   to_utc_iso_from_tw(form.get("start_at")),
        "expires_at": to_utc_iso_from_tw(form.get("expires_at")),
        "usage_limit": int(form.get("usage_limit")) if form.get("usage_limit") else None,
        "per_user_limit": int(form.get("per_user_limit")) if form.get("per_user_limit") else None,
        "is_active": form.get("is_active") == "on",
        "note": form.get("note") or None,
    }
    try:
        supabase.table("discounts").update(payload).eq("id", did).execute()
        flash("折扣碼已更新", "success")
    except Exception:
        flash("更新失敗，請稍後再試", "error")
    return redirect("/admin0363/features")

#admin 折扣碼 子頁
@app.route("/admin0363/features/discounts")
def admin_features_discounts():
    if not session.get("admin_logged_in"): return redirect("/admin0363")
    try:
        discounts = supabase.table("discounts").select("*").order("created_at", desc=True).execute().data or []
    except Exception:
        discounts = []
        flash("折扣碼資料表不存在，請先建立。", "error")
    return render_template("discounts.html", discounts=discounts, tab="features")

#admin 公告 子頁
@app.route("/admin0363/features/announcements")
def admin_features_announcements():
    if not session.get("admin_logged_in"): return redirect("/admin0363")
    # 先不查資料，之後補資料表/CRUD
    return render_template("announcements.html", items=[])

#首頁公告區
@app.get("/announcements.json")
def announcements_json():
    rows = (supabase.table("announcements")
            .select("id, title, content, start_at, end_at, is_active, created_at")
            .eq("is_active", True)
            .order("created_at", desc=True)
            .limit(20)
            .execute().data or [])
    return jsonify(rows)

# === admin首頁公告區: New / Create / Edit (optional) ===

def _admin_required():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

def _none_if_blank(v):
    v = (v or "").strip()
    return v or None

@app.get("/admin0363/announcements/new")
def admin_announcement_new():
    auth = _admin_required()
    if auth: return auth
    # 空白表單
    return render_template("admin_announcement_form.html", mode="new", ann=None)

@app.post("/admin0363/announcements")
def admin_announcement_create():
    auth = _admin_required()
    if auth: return auth

    title   = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    start_at = _none_if_blank(request.form.get("start_at"))  # datetime-local 值，可為空
    end_at   = _none_if_blank(request.form.get("end_at"))
    is_active = bool(request.form.get("is_active"))  # checkbox: on/None

    if not title and not content:
        flash(("error", "請至少輸入標題或內容"))
        return redirect("/admin0363/announcements/new")

    data = {
        "title": title,
        "content": content,
        "start_at": start_at,   # 直接給 ISO 字串，Postgres 會吃
        "end_at": end_at,
        "is_active": is_active
    }
    supabase.table("announcements").insert(data).execute()

    flash(("success", "公告已新增"))
    return redirect("/admin0363/features/announcements")


# （選用）編輯頁 & 更新；若暫時不需要，可先不加
@app.get("/admin0363/announcements/<int:ann_id>/edit")
def admin_announcement_edit(ann_id):
    auth = _admin_required()
    if auth: return auth

    row = (supabase.table("announcements")
           .select("*").eq("id", ann_id).single().execute().data)
    if not row:
        flash(("error", "找不到公告"))
        return redirect("/admin0363/features/announcements")
    return render_template("admin_announcement_form.html", mode="edit", ann=row)

@app.post("/admin0363/announcements/<int:ann_id>/update")
def admin_announcement_update(ann_id):
    auth = _admin_required()
    if auth: return auth

    title   = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    start_at = _none_if_blank(request.form.get("start_at"))
    end_at   = _none_if_blank(request.form.get("end_at"))
    is_active = bool(request.form.get("is_active"))

    supabase.table("announcements").update({
        "title": title,
        "content": content,
        "start_at": start_at,
        "end_at": end_at,
        "is_active": is_active
    }).eq("id", ann_id).execute()

    flash(("success", "公告已更新"))
    return redirect("/admin0363/features/announcements")

# 後台：公告清單（JSON）
@app.get("/admin0363/announcements")
def admin_announcement_index():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    rows = (supabase.table("announcements")
            .select("*")
            .order("created_at", desc=True)
            .execute().data or [])
    # 也可在這裡加上時間/狀態的標準化
    return jsonify(rows)

# === admin設定免運門檻 ===
def get_setting_num(key, default_val):
    """從 site_settings 讀取數值型設定，取不到就回傳 default_val"""
    try:
        r = supabase.table("site_settings").select("value").eq("key", key).single().execute()
        v = r.data.get("value") if r and r.data else None
        if v is None or str(v).strip() == "":
            return float(default_val)
        return float(v)
    except Exception:
        return float(default_val)

def set_setting_num(key, num):
    """寫入/覆寫數值型設定"""
    try:
        supabase.table("site_settings").upsert({
            "key": key,
            "value": str(num)
        }).execute()
        return True
    except Exception:
        return False

def get_shipping_rules():
    """取得免運門檻與運費（皆為 float）"""
    threshold = get_setting_num("free_shipping_threshold", 2000)
    ship_fee  = get_setting_num("shipping_fee", 80)
    return threshold, ship_fee




# admin後台 搜尋報表開始
@app.route("/admin0363/features/analytics", methods=["GET", "POST"])
def admin_features_analytics():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    tab = request.args.get("tab", "product")
    form = {}

    product_result = None
    member_result  = None

    if request.method == "POST":
        mode = request.form.get("mode")
        if mode == "product":
            # 表單
            form["keyword"]      = (request.form.get("keyword") or "").strip()
            form["p_start"]      = request.form.get("p_start") or ""
            form["p_end"]        = request.form.get("p_end") or ""
            form["all_products"] = True if request.form.get("all_products") in ("on","true","1") else False
            form["period"]       = "rolling"  # 未填日期時備用（一週/本月）

            product_result = _analytics_product(
                form["keyword"],
                form["period"],
                form["p_start"],
                form["p_end"],
                form["all_products"]
            )
            tab = "product"

        elif mode == "member":
            form["member_keyword"] = (request.form.get("member_keyword") or "").strip()
            form["start"] = request.form.get("start") or ""
            form["end"]   = request.form.get("end") or ""
            member_result = _analytics_member(form["member_keyword"], form["start"], form["end"])
            tab = "member"

    return render_template("admin_features_analytics.html",
                           tab=tab, form=form,
                           product_result=product_result,
                           member_result=member_result)

def _start_of_week_calendar(dt):
    # 以台北時區，將週一視為一週開始
    d = dt.astimezone(TW)
    monday = d - timedelta(days=(d.weekday()))  # 0=Mon
    return monday.replace(hour=0, minute=0, second=0, microsecond=0)

def _start_of_month(dt):
    d = dt.astimezone(TW)
    return d.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

# 出貨狀態（依你的資料庫為主）
SHIPPED_STATUSES = ["shipped", "Shipped", "已出貨", "已完成出貨", "出貨完成"]

def _analytics_product(keyword, period_mode, p_start, p_end, all_products=False):
    """
    商品銷售查詢（僅統計「已出貨」訂單）：
    - 有 p_start/p_end → 自訂區間
    - 否則 → 一週 / 本月
    - all_products=True 時忽略 keyword，取全部商品
    智慧備援：
      1) 先用 product_id IN products.id（轉字串）比對
      2) 若 0 筆且有 keyword → 用 product_name ILIKE 關鍵字
      3) 若仍 0 或勾「全部商品」→ 不套商品條件（只靠 order_id）
    """
    now = datetime.now(TW)

    # 1) 商品清單（把 id 轉成字串以符合 order_items.product_id=text）
    prod_q = supabase.table("products").select("id,name")
    if not all_products and keyword:
        prod_q = prod_q.ilike("name", f"%{keyword}%")
    prods = (prod_q.limit(1000).execute()).data or []

    prod_ids = [str(p["id"]) for p in prods]               # 轉字串
    name_map = {str(p["id"]): p["name"] for p in prods}    # 轉字串 key

    # 2) 只抓「已出貨」訂單
    def shipped_orders_between(start_iso=None, end_iso=None, limit=80000):
        q = supabase.table("orders").select("id").in_("status", SHIPPED_STATUSES)
        if start_iso:
            q = q.gte("created_at", start_iso)
        if end_iso:
            q = q.lte("created_at", end_iso)
        return (q.limit(limit).execute().data or [])

    # 3) 取品項（先 product_id 篩，撈不到再用 name，最後不套商品條件）
    def fetch_items(order_ids, filter_prod_ids, kw, all_flag):
        base = (
            supabase.table("order_items")
            .select("order_id,product_id,product_name,qty,price,subtotal")
            .in_("order_id", order_ids)
            .limit(50000)
        )
        used_product_filter = False
        items = []

        # 3-1 用 product_id IN (...) 試一次
        try:
            if filter_prod_ids:
                items = base.in_("product_id", filter_prod_ids).execute().data or []
                used_product_filter = True
        except Exception:
            items = []
            used_product_filter = False

        # 3-2 若 0 筆且有關鍵字且未勾全部商品 → 用 product_name 關鍵字
        if not items and (kw or "").strip() and not all_flag:
            try:
                items = base.ilike("product_name", f"%{kw}%").execute().data or []
                used_product_filter = False
            except Exception:
                items = []

        # 3-3 還是不行（或勾全部商品）→ 不套商品條件
        if not items:
            try:
                items = base.execute().data or []
                used_product_filter = False
            except Exception:
                items = []

        return items, used_product_filter

    # 4) 匯總工具（優先 subtotal；否則 qty*price）
    def aggregate(items):
        agg = {}         # {pid: {"name": 名稱, "qty": 數量, "amt": 金額}}
        for it in items:
            pid = str(it.get("product_id"))  # key 一律字串
            pname = (it.get("product_name") or name_map.get(pid) or f"商品 {pid}").strip()
            qty = int(it.get("qty") or 0)
            sub = it.get("subtotal")
            if sub is None:
                price = float(it.get("price") or 0)
                amt = qty * price
            else:
                amt = float(sub or 0)

            cell = agg.setdefault(pid, {"name": pname, "qty": 0, "amt": 0.0})
            cell["qty"] += qty
            cell["amt"] += amt
        return agg

    # === A. 區間模式 ===
    if p_start or p_end:
        if not p_end:
            p_end = now.strftime("%Y-%m-%d")
        if not p_start:
            p_start = p_end
        start_iso = f"{p_start}T00:00:00"
        end_iso = f"{p_end}T23:59:59"

        orders = shipped_orders_between(start_iso, end_iso)
        order_ids = [o["id"] for o in orders]

        items, used_pid_filter = fetch_items(order_ids, prod_ids, keyword, all_products)
        agg = aggregate(items)

        # rows
        rows, r_qty, r_amt = [], 0, 0.0
        # 若有用 product_id 篩 → 以 products 順序輸出；否則以匯總到的品項為準
        pids_to_show = prod_ids if used_pid_filter else list(agg.keys())
        for pid in pids_to_show:
            q = agg.get(pid, {}).get("qty", 0)
            a = agg.get(pid, {}).get("amt", 0.0)
            if q or a:
                rows.append({"name": agg.get(pid, {}).get("name", name_map.get(pid, f"商品 {pid}")),
                             "r_qty": q, "r_amt": a})
                r_qty += q
                r_amt += a

        # 商品數量顯示：若有用 product_id 篩就用 products 數；否則用匯總到的品項數
        product_count = len(prods) if used_pid_filter else len(agg)

        return {
            "product_count": product_count,   # 篩選後商品數（可能含本期 0 銷售）
            "row_count": len(rows),           # 本期有銷售的商品數（等於下方列數）
            "rows": rows,
            "range_mode": True,
            "range_qty": r_qty,
            "range_amount": r_amt,
            "range_start": p_start,
            "range_end": p_end,
            "week_qty": 0,
            "week_amount": 0,
            "month_qty": 0,
            "month_amount": 0,
        }

    # === B. 一週 / 本月 ===
    week_start = (now - timedelta(days=7)).replace(hour=0, minute=0, second=0, microsecond=0)
    week_end = now
    month_start = _start_of_month(now)
    month_end = now

    wk_orders = shipped_orders_between(week_start.isoformat(), week_end.isoformat(), limit=80000)
    mo_orders = shipped_orders_between(month_start.isoformat(), month_end.isoformat(), limit=120000)
    wk_ids = [o["id"] for o in wk_orders]
    mo_ids = [o["id"] for o in mo_orders]

    # 兩次各自撈、各自備援
    wk_items, wk_used_pid = fetch_items(wk_ids, prod_ids, keyword, all_products)
    mo_items, mo_used_pid = fetch_items(mo_ids, prod_ids, keyword, all_products)
    wk_agg = aggregate(wk_items)
    mo_agg = aggregate(mo_items)

    # rows
    rows = []
    week_qty = week_amt = month_qty = month_amt = 0
    # 若任何一個時段不是用 product_id 篩 → 以其匯總 key 為準做聯集
    if wk_used_pid and mo_used_pid:
        pid_set = set(prod_ids)
    else:
        pid_set = set(list(wk_agg.keys()) + list(mo_agg.keys()))

    for pid in pid_set:
        wq = wk_agg.get(pid, {}).get("qty", 0)
        wa = wk_agg.get(pid, {}).get("amt", 0.0)
        mq = mo_agg.get(pid, {}).get("qty", 0)
        ma = mo_agg.get(pid, {}).get("amt", 0.0)
        if any([wq, wa, mq, ma]):
            rows.append({
                "name": wk_agg.get(pid, {}).get("name") or mo_agg.get(pid, {}).get("name") or name_map.get(pid, f"商品 {pid}"),
                "w_qty": wq, "w_amt": wa, "m_qty": mq, "m_amt": ma
            })
            week_qty += wq; week_amt += wa; month_qty += mq; month_amt += ma

    product_count = len(prods) if (wk_used_pid and mo_used_pid) else len(pid_set)

    return {
         "product_count": product_count,   # 篩選後商品數
        "row_count": len(rows),           # 本期有銷售的商品數
        "rows": rows,
        "range_mode": False,
        "week_qty": week_qty, "week_amount": week_amt,
        "month_qty": month_qty, "month_amount": month_amt,
        "range_qty": 0, "range_amount": 0, "range_start": "", "range_end": ""
    }




def _analytics_member(keyword, start_date, end_date):
    """
    會員消費查詢（不依賴 orders.total）
    - 以 members + 關鍵字(姓名/Email/手機) 找到目標會員
    - 以時間區間篩選 orders（如需僅統計已付款/已出貨，請在 orders_q 加上 .eq(...)或 .in_(...)）
    - 以 order_items 匯總訂單金額 (sum(qty * price) 或 sum(quantity * unit_price))
    - 彙總到會員層級：訂單數、總金額、最近購買時間
    """
    # 1) 找會員
    mem_q = supabase.table("members").select("id,name,email,phone")
    if keyword:
        kw = f"%{keyword}%"
        found = {}
        for col in ["name", "email", "phone"]:
            res = supabase.table("members").select("id,name,email,phone")\
                    .ilike(col, kw).limit(1000).execute().data or []
            for m in res:
                found[m["id"]] = m
        members = list(found.values())
    else:
        members = mem_q.limit(1000).execute().data or []

    if not members:
        return {"member_count": 0, "order_count": 0, "total_amount": 0, "avg_amount": 0, "rows": []}

    mem_map = {m["id"]: m for m in members}
    mem_ids = list(mem_map.keys())

    # 2) 取訂單（僅取必要欄位）
    orders_q = supabase.table("orders").select("id,member_id,created_at").in_("member_id", mem_ids)
    if start_date:
        orders_q = orders_q.gte("created_at", f"{start_date}T00:00:00")
    if end_date:
        orders_q = orders_q.lte("created_at", f"{end_date}T23:59:59")
    # 如需僅統計已出貨/已付款，可打開：
    # orders_q = orders_q.in_("status", SHIPPED_STATUSES)
    # orders_q = orders_q.eq("payment_status", "paid")

    orders = orders_q.limit(20000).execute().data or []
    if not orders:
        return {"member_count": 0, "order_count": 0, "total_amount": 0, "avg_amount": 0, "rows": []}

    order_ids = [o["id"] for o in orders]
    order_created_at = {o["id"]: o.get("created_at") for o in orders}

    # 3) 以 order_items 匯總每張訂單金額
    items = supabase.table("order_items").select("order_id,qty,price")\
                     .in_("order_id", order_ids).limit(50000).execute().data or []
    if not items:
        items = supabase.table("order_items").select("order_id,quantity,unit_price")\
                         .in_("order_id", order_ids).limit(50000).execute().data or []
    order_amount = {}
    for it in items:
        oid = it["order_id"]
        qty = int(it.get("qty") or it.get("quantity") or 0)
        price = float(it.get("price") or it.get("unit_price") or 0)
        order_amount[oid] = order_amount.get(oid, 0.0) + qty * price

    # 4) 彙總到會員層級
    per = {}  # {member_id: {"count":x, "sum":y, "last":datetime}}
    for o in orders:
        oid = o["id"]
        mid = o["member_id"]
        amt = float(order_amount.get(oid, 0.0))
        created = order_created_at.get(oid)

        cell = per.setdefault(mid, {"count": 0, "sum": 0.0, "last": None})
        cell["count"] += 1
        cell["sum"] += amt

        try:
            dt = parser.parse(created).astimezone(TW) if created else None
        except Exception:
            dt = None
        if dt and (cell["last"] is None or dt > cell["last"]):
            cell["last"] = dt

    # 5) 組表格資料
    rows = []
    total_orders = 0
    total_amount = 0.0
    for mid, info in per.items():
        m = mem_map.get(mid, {})
        total_orders += info["count"]
        total_amount += info["sum"]
        rows.append({
            "member_name": m.get("name") or "(未命名)",
            "member_email": m.get("email") or "",
            "member_phone": m.get("phone") or "",
            "order_count": info["count"],
            "total_amount": info["sum"],
            "last_order_at": info["last"].strftime("%Y-%m-%d %H:%M") if info["last"] else "-"
        })

    avg_amount = (total_amount / total_orders) if total_orders else 0.0
    rows.sort(key=lambda r: r["total_amount"], reverse=True)

    return {
        "member_count": len(per),
        "order_count": total_orders,
        "total_amount": total_amount,
        "avg_amount": avg_amount,
        "rows": rows
    }
# admin後台 搜尋報表 結束


@app.route("/admin0363/mark_seen_orders", methods=["POST"])
def mark_seen_orders():
    session["seen_orders"] = True
    return '', 204

#admin登出功能
@app.route("/admin0363/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect("/admin0363")



# ✅ 驗證碼確認
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        code = request.form['code']
        if code == session.get('reset_code'):
            # ✅ 記錄 Email 以便後續 reset 使用
            reset_user = session.get('reset_user')
            if reset_user:
                session['reset_email'] = reset_user['email']

            flash("驗證成功，請設定新密碼。", "success")
            return redirect('/reset-password')
        else:
            flash("驗證碼錯誤，請重新輸入。", "danger")
    return render_template("verify.html")



# ✅ 密碼重置
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        flash("請先完成驗證步驟")
        return redirect('/forgot')

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            return render_template("reset_password.html", error="請填寫所有欄位")

        if new_password != confirm_password:
            return render_template("reset_password.html", error="兩次輸入的密碼不一致")

        email = session['reset_email']

        # ✅ 改為 members 資料表
        user_res = supabase.table("members").select("*").eq("email", email).execute()
        if not user_res.data:
            return render_template("reset_password.html", error="找不到此帳號")

        user_id = user_res.data[0]['id']
        supabase.table("members").update({"password": new_password}).eq("id", user_id).execute()

        # 清除 session
        session.pop('reset_email', None)
        session.pop('reset_code', None)
        session.pop('reset_user', None)

        flash("密碼已重設成功，請重新登入")
        return redirect('/login')

    return render_template("reset_password.html")





@app.route('/login', methods=['GET', 'POST'])
def login():
    next_page = request.args.get('next')  # 例如 ?next=cart

    if request.method == 'POST':
        account = request.form.get('account')
        password = request.form.get('password')

        if not account or not password:
            return render_template("login.html", error="請輸入帳號與密碼")

        res = (supabase.table("members")
               .select("id, account, password, name, phone, address")
               .eq("account", account).execute())

        if res.data and res.data[0]['password'] == password:
            user = res.data[0]
            session['user'] = user
            session['member_id'] = user['id']

            # ✅ 第一次登入自動發放新會員購物金（若後台金額>0且尚未發過）
            try:
                _auto_grant_signup_wallet(session['member_id'])
            except Exception:
                current_app.logger.exception("[wallet] auto grant (platform login) failed")

            # ★ 新增：立即刷新頁首購物金徽章（用 credits 加總，兼容你目前 DB）
            try:
                bres = (supabase.table("wallet_credits")
                        .select("amount_cents")
                        .eq("member_id", session['member_id']).execute())
                session['wallet_balance_cents'] = sum(int(r.get('amount_cents') or 0) for r in (bres.data or []))
            except Exception:
                session['wallet_balance_cents'] = 0

            # ✅ 判斷是否有缺資料
            if not user.get('name') or not user.get('phone') or not user.get('address'):
                session['incomplete_profile'] = True
            else:
                session.pop('incomplete_profile', None)

            # 支援 ?next=wallet 直接帶去錢包頁
            if next_page == 'wallet':
                return redirect('/member/wallet')
            return redirect('/cart' if next_page == 'cart' else '/')
        else:
            return render_template("login.html", error="帳號或密碼錯誤")

    return render_template("login.html")




# === 第三方登入：導向同意頁開始 ===

# 啟動登入：把 next 存起來，取消或成功都可以導回
@app.route("/login/facebook")
def login_facebook():
    # 產生 https 的絕對回呼網址，需與 FB 後台的 Valid OAuth Redirect URIs 完全一致
    redirect_uri = url_for("login_facebook_callback", _external=True, _scheme="https")
    return oauth.facebook.authorize_redirect(redirect_uri)


# ========= Google OAuth =========

def _google_redirect_uri():
    return url_for("login_google_callback", _external=True)

@app.route("/login/google")
def login_google():
    # 紀錄回跳頁（相對路徑才允許）
    next_url = request.args.get("next") or url_for("index")
    try:
        from urllib.parse import urlparse
        p = urlparse(next_url)
        if p.netloc or "/login" in p.path:
            next_url = url_for("index")
    except Exception:
        next_url = url_for("index")
    session["oauth_next"] = next_url

    redirect_uri = url_for("login_google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/login/google/callback")
def login_google_callback():
    # 1) 交換 access token（不解析 id_token、不用 nonce）
    try:
        token = oauth.google.authorize_access_token()
        if not token or not isinstance(token, dict):
            return redirect(url_for("index"))
    except Exception:
        current_app.logger.exception("[GOOGLE] authorize_access_token failed")
        return redirect(url_for("index"))

    # 2) 直接打絕對的 userinfo_endpoint 取得使用者資料
    sub = email = name = picture = None
    try:
        meta = oauth.google.load_server_metadata()
        userinfo_url = meta.get("userinfo_endpoint") or "https://openidconnect.googleapis.com/v1/userinfo"
        resp = oauth.google.get(userinfo_url, token=token)
        data = resp.json() if resp else {}
        sub = data.get("sub")
        email = data.get("email")
        name = data.get("name") or data.get("given_name")
        picture = data.get("picture")
    except Exception:
        current_app.logger.exception("[GOOGLE] get userinfo failed")

    # 3) 沒拿到最基本識別（sub 或 email）就回首頁
    if not (sub or email):
        return redirect(url_for("index"))

    # 4) upsert 會員 + 寫 session（與 LINE 同樣結構）
    member = upsert_member_from_oauth(
        provider="google", sub=sub, email=email, name=name, avatar_url=picture
    )

    session["member_id"] = member["id"]
    # ★ 第一次登入自動發放新會員購物金
    try:
        _auto_grant_signup_wallet(session["member_id"])
    except Exception:
        current_app.logger.exception("[wallet] auto grant failed")
    session["user"] = {
        "account": member.get("account") or (member.get("email") or "google_user"),
        "email": member.get("email"),
        "name": member.get("name") or name,
        "provider": "google",
        "avatar_url": member.get("avatar_url") or picture,
    }
    session["account"] = session["user"]["account"]
    session["incomplete_profile"] = not all([
        member.get("name"), member.get("phone"), member.get("address")
    ])
    session.permanent = True
    session.modified = True

    # 5) 安全 next_url（只允許站內相對路徑，且避開 /login）
    next_url = session.pop("oauth_next", None) or url_for("index")
    try:
        from urllib.parse import urlparse
        p = urlparse(next_url)
        if p.netloc or "/login" in p.path:
            next_url = url_for("index")
    except Exception:
        next_url = url_for("index")

    # 6) 回跳並禁快取，避免瀏覽器快取干擾登入狀態
    resp = redirect(next_url, code=302)
    resp.headers["Cache-Control"] = "no-store"
    return resp



# === Facebook 回呼（加強版）===
@app.route("/login/facebook/callback")
def login_facebook_callback():
    # --- A) Facebook 直接回錯（含使用者取消、1349220 等）---
    fb_err = (
        request.args.get("error")
        or request.args.get("error_code")
        or request.args.get("error_reason")
        or request.args.get("error_description")
    )
    if fb_err:
        code = request.args.get("error_code")
        reason = request.args.get("error_reason")
        msg = request.args.get("error_message") or request.args.get("error_description")
        app.logger.warning("[FB][callback] error_code=%s error=%s reason=%s message=%s",
                           code, request.args.get("error"), reason, msg)

        # 針對 1349220（App 未上線/受限）用不同狀態字串，前端可顯示更清楚
        status = "app_unavailable" if str(code) == "1349220" else "error"

        next_url = session.pop("oauth_next", url_for("login"))
        return redirect(f"{next_url}?oauth=facebook&status={status}", code=302)

    try:
        # --- B) 兌換 access_token（Authlib 會驗 state）---
        # 備註：有些情況需要帶同一個 redirect_uri；若你發現偶發 "redirect_uri mismatch"，
        # 可解除下一行註解傳同一個 callback URL。
        # token = oauth.facebook.authorize_access_token(redirect_uri=url_for("login_facebook_callback", _external=True, _scheme="https"))
        token = oauth.facebook.authorize_access_token()
        if not isinstance(token, dict) or not token.get("access_token"):
            raise RuntimeError("facebook authorize_access_token() 回傳異常")

        # --- C) 取使用者資料（容錯）：---
        # 寬高指定可得較清晰頭像；若沒有 email 也允許登入
        resp = oauth.facebook.get("me?fields=id,name,email,picture.width(256).height(256)")
        try:
            data = resp.json() if hasattr(resp, "json") else {}
        except Exception:
            data = {}

        sub = (data or {}).get("id")
        if not sub:
            # 少見：Graph 回來缺 id，直接視為失敗
            abort(400, "Facebook 回傳缺少 id")

        picture = (((data.get("picture") or {}).get("data")) or {})
        avatar_url = picture.get("url")

        member = upsert_member_from_oauth(
            provider="facebook",
            sub=sub,
            email=data.get("email"),
            name=data.get("name"),
            avatar_url=avatar_url,
        )

        # --- D) 建立登入狀態 ---
        session["member_id"] = member["id"]
        # ★ 第一次登入自動發放新會員購物金
        try:
            _auto_grant_signup_wallet(session["member_id"])
        except Exception:
            current_app.logger.exception("[wallet] auto grant failed")
        session["user"] = {
            "account": member.get("account") or (member.get("email") or "facebook_user"),
            "email": member.get("email"),
            "name": member.get("name") or data.get("name"),
            "provider": "facebook",
            "avatar_url": member.get("avatar_url") or avatar_url,
        }
        session["incomplete_profile"] = not all([
            member.get("name"), member.get("phone"), member.get("address")
        ])

        # --- E) 乾淨的安全跳轉（只允許站內 & 非 /login）---
        next_url = session.pop("oauth_next", None) or url_for("index")
        from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
        p = urlparse(next_url)

        # 外站/含 netloc → 改回首頁；避免 open redirect
        if p.netloc:
            next_url = url_for("index")
        else:
            # 清理掉任何 oauth 訊息參數，避免殘留
            query = [(k, v) for (k, v) in parse_qsl(p.query) if k not in {"oauth", "status", "error"}]
            clean = p._replace(query=urlencode(query))
            next_url = urlunparse(clean)
            if "/login" in (p.path or ""):
                next_url = url_for("index")

        resp = redirect(next_url, code=302)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    except Exception as e:
        app.logger.exception("[FB][callback] exchange failed: %s", e)
        next_url = session.pop("oauth_next", url_for("login"))
        return redirect(f"{next_url}?oauth=facebook&status=error", code=302)


# === 第三方登入：導向同意頁結束 ===


# ----- LINE provider 註冊 -----
# ========= LINE OAuth =========

def _line_redirect_uri():
    return url_for('login_line_callback', _external=True, _scheme="https")

@app.route("/login/line")
def login_line():
    next_url = request.args.get("next") or url_for("index")
    session["oauth_next"] = next_url
    # 一律用實際 callback 絕對網址，需與 LINE 後台設定完全一致
    redirect_uri = url_for("login_line_callback", _external=True)
    return oauth.line.authorize_redirect(redirect_uri=redirect_uri)

# 回呼〔取代整個 /login/line/callback 〕
@app.route("/login/line/callback")
def login_line_callback():
    # 使用者取消授權 → 回首頁
    if request.args.get("error"):
        return redirect(url_for("index"))

    # 1) 交換 access token（此時不會自動驗 id_token）
    try:
        token = oauth.line.authorize_access_token()
        if not token or not isinstance(token, dict):
            current_app.logger.error("[LINE] empty token or invalid token type: %r", token)
            return redirect(url_for("index"))
    except Exception:
        current_app.logger.exception("[LINE] authorize_access_token failed")
        return redirect(url_for("index"))

    # 2) 取 LINE Profile
    sub = name = picture = email = None
    try:
        prof = oauth.line.get("https://api.line.me/v2/profile", token=token).json()
        sub = prof.get("userId")
        name = prof.get("displayName")
        picture = prof.get("pictureUrl")
    except Exception:
        current_app.logger.exception("[LINE] get profile failed")

    # 3) 可選：若 token 內仍然有 id_token，嘗試用 verify 端點換 email（失敗就略過）
    try:
        id_token = token.get("id_token")
        client_id = os.getenv("LINE_CHANNEL_ID") or os.getenv("LINE_CLIENT_ID")
        if id_token and client_id:
            vr = requests.post(
                "https://api.line.me/oauth2/v2.1/verify",
                data={"id_token": id_token, "client_id": client_id},
                timeout=6,
            )
            if vr.ok:
                claims = vr.json()
                email = claims.get("email") or email
    except Exception:
        current_app.logger.exception("[LINE] verify id_token failed")

    # 4) 缺 sub 視為失敗
    if not sub:
        return redirect(url_for("index"))

    # 5) upsert + 寫 session
    member = upsert_member_from_oauth(
        provider="line", sub=sub, email=email, name=name, avatar_url=picture
    )
    session["member_id"] = member["id"]
    # ★ 第一次登入自動發放新會員購物金
    try:
        _auto_grant_signup_wallet(session["member_id"])
    except Exception:
        current_app.logger.exception("[wallet] auto grant failed")
    session["user"] = {
        "account": member.get("account") or (member.get("email") or "line_user"),
        "email": member.get("email"),
        "name": member.get("name") or name,
        "provider": "line",
        "avatar_url": member.get("avatar_url") or picture,
    }
    session["account"] = session["user"]["account"]
    session["incomplete_profile"] = not all([
        member.get("name"), member.get("phone"), member.get("address")
    ])
    session.permanent = True
    session.modified = True
    current_app.logger.info("[LINE] session user set: %s", session.get("user"))

    # 6) 安全 next_url（只允許站內）
    next_url = session.pop("oauth_next", None) or url_for("index")
    try:
        from urllib.parse import urlparse
        p = urlparse(next_url)
        if p.netloc or "/login" in p.path:
            next_url = url_for("index")
    except Exception:
        next_url = url_for("index")

    # 7) 回首頁 + 禁快取
    resp = redirect(next_url, code=302)
    resp.headers["Cache-Control"] = "no-store"
    return resp

# 觸發登入（導去 LINE 授權）
def _line_redirect_uri():
    return url_for('login_line_callback', _external=True, _scheme="https")


@app.before_request
def _force_permanent_session():
    session.permanent = True

#除錯端點
@app.get("/whoami")
def whoami():
    return jsonify({
        "member_id": session.get("member_id"),
        "user": session.get("user"),
        "has_cookie": bool(request.cookies.get(app.config.get("SESSION_COOKIE_NAME", "session")))
    })


@app.route('/get_profile')
def get_profile():
    if 'member_id' not in session:
        # ✅ 未登入 → 回 401，讓前端知道要跳去登入
        return jsonify({"error": "unauthorized"}), 401

    member_id = session['member_id']  # 直接拿字串即可
    res = (
        supabase.table("members")
        .select("name, phone, address, note")
        .eq("id", member_id)
        .limit(1)
        .execute()
    )

    return jsonify(res.data[0] if res.data else {})





@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")

    # --- POST: 註冊 ---
    account  = (request.form.get('account')  or '').strip()
    email    = (request.form.get('email')    or '').strip()
    password = (request.form.get('password') or '').strip()
    username = account

    if not account or not email or not password:
        return render_template("register.html", error="請完整填寫帳號、Email 與密碼")

    # 帳號是否已存在
    exist = supabase.table("members").select("id").eq("account", account).limit(1).execute()
    if exist.data:
        return render_template("register.html", error="此信箱已被使用")

    try:
        # 建議寫入 UTC（避免 tz 未定義、排序也穩定）
        created_at = datetime.utcnow().isoformat() + "Z"

        # 不給 id 由 Supabase 產生
        resp = supabase.table("members").insert({
            "account": account,
            "email": email,
            "password": password,   # 目前存明碼；之後可改雜湊
            "username": username,
            "created_at": created_at,
        }).execute()

        # 取得新會員 id（保險：若 resp 無資料再查一次）
        new_id = None
        if resp.data and len(resp.data) > 0 and 'id' in resp.data[0]:
            new_id = resp.data[0]['id']
        else:
            q = supabase.table("members").select("id").eq("account", account).limit(1).execute()
            if q.data:
                new_id = q.data[0]['id']

        # 直接登入
        session['user'] = {'account': account, 'email': email}
        if new_id:
            session['member_id'] = new_id

            # ★ 新增：第一次註冊即自動發放新會員購物金（平台註冊）
            try:
                _auto_grant_signup_wallet(session["member_id"])
            except Exception:
                current_app.logger.exception("[wallet] auto grant (platform register) failed")

        # 首次登入引導補資料
        session['incomplete_profile'] = True

        return render_template("register_success.html")

    except Exception as e:
        app.logger.error(f"🚨 註冊錯誤：{e}")
        return render_template("register.html", error="註冊失敗，請稍後再試")


# === Admin: 購物金設定 ===
@app.get("/admin0363/wallet/settings")
def admin_wallet_settings():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    cfg = _wallet_settings()
    return render_template("admin_wallet_settings.html", cfg=cfg)



@app.post("/admin0363/wallet/settings")
def admin_wallet_settings_save():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    # 後台以「元」存到 site_settings，顯示也用元
    try:
        signup_amount_nt = max(0.0, float(request.form.get("signup_amount") or 0))
    except Exception:
        signup_amount_nt = 0.0

    try:
        signup_valid_days = max(0, int(request.form.get("signup_valid_days") or 0))
    except Exception:
        signup_valid_days = 0

    # 【新增】購物金最低可使用訂單金額（元）
    try:
        min_order_amount_nt = max(0.0, float(request.form.get("min_order_amount") or 0))
    except Exception:
        min_order_amount_nt = 0.0

    ok1 = set_setting_num("wallet_signup_amount_nt", signup_amount_nt)
    ok2 = set_setting_num("wallet_signup_valid_days", signup_valid_days)
    ok3 = set_setting_num("wallet_min_order_amount_nt", min_order_amount_nt)


    flash(
        "購物金設定已儲存" if (ok1 and ok2 and ok3) else "儲存失敗，請稍後再試",
        "success" if (ok1 and ok2 and ok3) else "error"
    )
    return redirect("/admin0363/wallet/settings")


# === Admin: 購物金發放（表單 + 搜尋） ===
@app.get("/admin0363/wallet/grant")
def admin_wallet_grant_form():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    q = (request.args.get("q") or "").strip()
    candidates = []
    if q:
        # 模糊比對 email / 姓名 / 電話 / 帳號 / username
        pattern = f"%{q}%"
        try:
            res = (
                supabase.table("members")
                .select("id,name,email,phone")
                .or_(
                    "email.ilike.{p},name.ilike.{p},phone.ilike.{p},account.ilike.{p},username.ilike.{p}"
                    .format(p=pattern)
                )
                .order("id", desc=True)
                .limit(100)
                .execute()
            )
            candidates = res.data or []
        except Exception as e:
            current_app.logger.exception("search members failed: %s", e)
            candidates = []

    return render_template("admin_wallet_grant.html", candidates=candidates)


# === Admin: 購物金發放（提交） ===
@app.post("/admin0363/wallet/grant")
def admin_wallet_grant():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    form = request.form

    # ① 同時支援單一 member_id（來自每列表單）或多筆 member_ids（逗號分隔）
    raw_ids = (form.get("member_ids") or "").strip()
    single_id = (form.get("member_id") or "").strip()
    if single_id and not raw_ids:
        raw_ids = single_id

    # 金額用「元」
    try:
        amount_nt = float(form.get("amount") or 0)
    except Exception:
        amount_nt = 0.0

    reason = (form.get("reason") or "manual").strip() or "manual"
    note = (form.get("note") or "").strip() or None
    expires_raw = (form.get("expires_at") or "").strip()  # 可能是 'YYYY-MM-DD' 或空字串

    if not raw_ids or amount_nt <= 0:
        flash("請輸入會員與正確金額", "error")
        return redirect("/admin0363/wallet/grant")

    amount_cents = int(round(amount_nt * 100))
    ids = [x.strip() for x in raw_ids.split(",") if x.strip()]

    # ② 到期日：你的表單是 <input type="date">，只有日期
    #    若有填，預設取台灣時間當天的 23:59 轉成 UTC ISO
    expires_iso = None
    if expires_raw:
        try:
            # 'YYYY-MM-DD' -> 'YYYY-MM-DDT23:59'
            local_dt = f"{expires_raw}T23:59"
            expires_iso = to_utc_iso_from_tw(local_dt)
        except Exception:
            expires_iso = None

    ok_cnt, fail_cnt = 0, 0
    for mid in ids:
        if _grant_wallet(
            mid,
            amount_cents,
            reason=reason,
            expires_at_iso=expires_iso,
            issued_by_admin=session.get("admin_id"),
            note=note,
        ):
            ok_cnt += 1
        else:
            fail_cnt += 1

    flash(
        f"發放完成：成功 {ok_cnt} 筆，失敗 {fail_cnt} 筆",
        "success" if fail_cnt == 0 else "warning",
    )
    return redirect("/admin0363/wallet/grant")

# === Member: 我的購物金 ===
@app.get("/member/wallet")
def member_wallet():
    mid = session.get("member_id")
    if not mid:
        return redirect("/login?next=wallet")

    # 讀發放/異動紀錄（wallet_credits）
    try:
        rows = (
            supabase.table("wallet_credits")
            .select("*")
            .eq("member_id", mid)
            .order("id", desc=True)
            .limit(200)
            .execute()
        ).data or []
    except Exception:
        rows = []

    # ✅ 用交易明細計算『可用餘額（分）』
    available_cents = _calc_available_wallet_cents(rows)

    # （可選）把最新可用額也塞回 session，讓 header 徽章一致
    session["wallet_balance_cents"] = max(int(available_cents or 0), 0)

    return render_template(
        "member_wallet.html",
        available_cents=available_cents,
        rows=rows,
    )


@app.context_processor
def inject_wallet_badge_amount():
    amt = (session.get("wallet_balance_cents") or 0) // 100
    return {"wallet_badge_amount": amt}


# === Admin: 購物金查詢 / 報表 ===
@app.get("/admin0363/wallet/report")
def admin_wallet_report():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    # 1) 讀取查詢條件
    date_from = (request.args.get("from") or "").strip()
    date_to   = (request.args.get("to") or "").strip()
    reason    = (request.args.get("reason") or "").strip()   # e.g. signup_bonus/manual/order_checkout/refund
    q         = (request.args.get("q") or "").strip()

    # 2) 基礎查詢：wallet_credits 最近 200 筆（可依條件縮小）
    query = (supabase.table("wallet_credits")
             .select("id,member_id,amount_cents,reason,created_at,expires_at,related_order_id,note")
             .order("id", desc=True))

    # 日期過濾（created_at，date-only 以當天 00:00~23:59:59）
    if date_from:
        query = query.gte("created_at", f"{date_from}T00:00:00")
    if date_to:
        query = query.lte("created_at", f"{date_to}T23:59:59")
    if reason:
        query = query.eq("reason", reason)

    rows = (query.limit(200).execute().data) or []

    # 3) 會員關鍵字過濾（email / name / phone / account / username）
    member_map = {}
    if q:
        # 先撈出所有 rows 的 member_id
        mids = list({r["member_id"] for r in rows if r.get("member_id")})
        if mids:
            # 撈會員資料做過濾 + 之後顯示
            mem_rows = (supabase.table("members")
                        .select("id,name,email,phone,account,username")
                        .in_("id", mids).execute().data) or []
            # 建立查詢字典
            member_map = {m["id"]: m for m in mem_rows}
            def _match(m):
                s = q.lower()
                return (s in (m.get("email") or "").lower()
                        or s in (m.get("name") or "").lower()
                        or s in (m.get("phone") or "").lower()
                        or s in (m.get("account") or "").lower()
                        or s in (m.get("username") or "").lower())
            allow_ids = {m["id"] for m in mem_rows if _match(m)}
            rows = [r for r in rows if r.get("member_id") in allow_ids]
        else:
            rows = []

    # 4) 合計（以「分」為單位；模板寫法用 // 100，所以這裡傳分）
    total_in_cents = 0
    total_out_cents = 0
    for r in rows:
        amt = int(r.get("amount_cents") or 0)
        if amt >= 0:
            total_in_cents += amt
        else:
            total_out_cents += (-amt)
    net_cents = total_in_cents - total_out_cents

    # 5) 傳給模板（注意：這裡傳的是「分」→ 可直接配合你的 {{ (xx // 100) }} 寫法）
    return render_template(
        "admin_wallet_report.html",
        rows=rows,
        member_map=member_map,        # ← 供模板顯示姓名/Email
        total_in=total_in_cents,      # ← 分
        total_out=total_out_cents,    # ← 分
        net=net_cents,                # ← 分（模板用 {{ (net // 100) }}）
        # 把查詢條件回填到表單
        date_from=date_from,
        date_to=date_to,
        reason=reason,
    )

# === 團購主管理 ===
# ===== 團購主管理 =====
@app.get("/admin0363/affiliates")
def admin_affiliates():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    try:
        res = (
            supabase.table("affiliates")
            .select("*")
            .order("created_at", desc=True)
            .execute()
        )
        affiliates = res.data or []
    except Exception as e:
        app.logger.exception("[affiliates] load failed: %s", e)
        affiliates = []

    return render_template("admin_affiliates.html", affiliates=affiliates)


@app.post("/admin0363/affiliates/create")
def admin_affiliates_create():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    name = (request.form.get("name") or "").strip()
    code = (request.form.get("code") or "").strip()
    commission_rate = request.form.get("commission_rate")
    is_active = bool(request.form.get("is_active"))

    if not name or not code:
        flash("請填寫團購主名稱與代碼", "error")
        return redirect("/admin0363/affiliates")

    try:
        commission_rate = float(commission_rate or 0)
    except Exception:
        commission_rate = 0

    try:
        supabase.table("affiliates").insert({
            "name": name,
            "code": code,
            "commission_rate": commission_rate,
            "is_active": is_active
        }).execute()
        flash("團購主已新增", "success")
    except Exception as e:
        app.logger.exception("[affiliates] create failed: %s", e)
        flash("新增失敗，請確認 code 是否重複或欄位名稱是否正確", "error")

    return redirect("/admin0363/affiliates")


@app.post("/admin0363/affiliates/update/<aid>")
def admin_affiliates_update(aid):
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    name = (request.form.get("name") or "").strip()
    code = (request.form.get("code") or "").strip()
    commission_rate = request.form.get("commission_rate")
    is_active = request.form.get("is_active") == "true"

    if not name or not code:
        flash("名稱與代碼不可空白", "error")
        return redirect("/admin0363/affiliates")

    try:
        commission_rate = float(commission_rate or 0)
    except Exception:
        commission_rate = 0

    try:
        supabase.table("affiliates").update({
            "name": name,
            "code": code,
            "commission_rate": commission_rate,
            "is_active": is_active
        }).eq("id", aid).execute()
        flash("團購主已更新", "success")
    except Exception as e:
        app.logger.exception("[affiliates] update failed: %s", e)
        flash("更新失敗", "error")

    return redirect("/admin0363/affiliates")


@app.route('/logout')
def logout():
    # 只清「會員相關」的 session，不動後台登入狀態
    for k in ['member_id', 'user', 'account', 'wallet_balance_cents',
              'has_new_reply', 'incomplete_profile', 'cart', 'cart_discount']:
        session.pop(k, None)

    # 不刪整個 session cookie，避免 admin_logged_in 也被清掉
    return redirect(url_for('index'))



@app.route('/about')
def about():
    return render_template('about.html')


#FB隱私權
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/delete-account')
def delete_account():
    return render_template('delete_account.html')



@app.route('/cart', methods=['GET', 'POST'])
def cart():
    # 先把購物車從 session 拿出來
    cart_items = session.get('cart', [])

    # --- 如果是 POST：可能是調整商品數量、移除、或套用/取消折扣碼 ---
    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()
        # 1) 商品異動（increase / decrease / remove）
        if action in ('increase', 'decrease', 'remove'):
            product_id = request.form.get('product_id')
            option = (request.form.get('option') or '')
            for item in cart_items:
                if item.get('product_id') == product_id and (item.get('option') or '') == option:
                    if action == 'increase':
                        item['qty'] = int(item.get('qty') or 1) + 1
                    elif action == 'decrease':
                        q = int(item.get('qty') or 1)
                        item['qty'] = q - 1 if q > 1 else 1
                    elif action == 'remove':
                        cart_items.remove(item)
                    break
            session['cart'] = cart_items
            return redirect(url_for('cart'))

        # 2) 套用折扣碼
        if action == 'apply_discount':
            # 以目前購物車小計（不含運費）驗證
            subtotal = 0.0
            for it in cart_items:
                price = float(it.get('price') or 0)
                qty = int(it.get('qty') or 1)
                subtotal += price * qty
            ok, msg, info = validate_discount_for_cart(request.form.get('discount_code', ''), subtotal)
            if ok:
                session['cart_discount'] = info  # 只存必要資訊；實際折抵在 GET 會再重算
            else:
                session.pop('cart_discount', None)
            flash(msg)
            return redirect(url_for('cart'))

        # 3) 取消折扣碼
        if action == 'remove_discount':
            session.pop('cart_discount', None)
            flash("已取消折扣碼")
            return redirect(url_for('cart'))

        # 其他未知 action：直接回購物車
        return redirect(url_for('cart'))

    # ---- GET：顯示購物車 ----
    products = []
    total = 0.0

    for item in cart_items:
        pid = item.get('product_id')
        if not pid:
            continue

        # 加入購物車時已決定的計價欄位
        unit_price = float(item.get('price') or 0)                 # 單價（計價用）
        unit_compare = float(item.get('original_price') or 0)      # 原價（顯示刪除線）
        unit_discount = float(item.get('discount_price') or 0)     # 折扣價（若有且 < 原價）
        qty = int(item.get('qty') or 1)

        # 從 DB 取補充資訊（不覆寫價格）
        db = supabase.table("products").select("name,image,images,product_type") \
                     .eq("id", pid).single().execute()
        dbp = db.data or {}

        images = item.get('images') or dbp.get('images') or []
        image = item.get('image') or dbp.get('image') \
                or (images[0] if images else None)

        # 🔹 套組內容整理（給前端顯示）
        bundle_lines = []
        if (item.get('product_type') or dbp.get('product_type')) == 'bundle':
            if isinstance(item.get('bundle_items'), list) and item['bundle_items']:
                for c in item['bundle_items']:
                    nm = c.get('name') or c.get('title') or c.get('product_name') or c.get('label')
                    q = int(c.get('qty') or c.get('count') or 1)
                    if nm:
                        nm = _clean_bundle_label(nm)
                        bundle_lines.append(f"{nm} × {q}" if q > 1 else nm)
            elif isinstance(item.get('bundle_selected'), list):
                for s in item['bundle_selected']:
                    if isinstance(s, dict):
                        nm = s.get('name') or s.get('title') or s.get('label') or str(s.get('value') or '')
                        q = int(s.get('qty') or s.get('count') or 1)
                        if nm:
                            nm = _clean_bundle_label(nm)
                            bundle_lines.append(f"{nm} × {q}" if q > 1 else nm)
                    else:
                        if s:
                            bundle_lines.append(str(s))
            elif item.get('option'):
                text = str(item['option']).strip()
                parts = [_clean_bundle_label(p) for p in re.split(r'[,\n、|｜]+', text) if p.strip()]
                bundle_lines.extend(parts)

        product_out = {
            'id': pid,
            'name': dbp.get('name') or item.get('name'),
            'product_type': item.get('product_type') or dbp.get('product_type'),

            # ✅ 套組價格欄位（若為套組）
            'bundle_price':   item.get('bundle_price'),
            'bundle_compare': item.get('bundle_compare'),

            # 前端顯示/計算會用到的欄位
            'price': unit_price,
            'original_price': unit_compare if unit_compare > 0 else unit_price,
            'discount_price': unit_discount if (unit_discount and unit_compare and unit_discount < unit_compare) else 0.0,
            'qty': qty,
            'subtotal': unit_price * qty,

            # 🔹 給模板顯示的套組行
            'bundle_lines': bundle_lines,

            'option': item.get('option', ''),
            'image': image,
            'images': images,
        }

        products.append(product_out)
        total += product_out['subtotal']

        # 運費計算（讀 site_settings）
    free_shipping_threshold, default_shipping_fee = get_shipping_rules()
    shipping_fee = 0.0 if total >= free_shipping_threshold else float(default_shipping_fee)

    # === 購物金最低使用門檻（元）===
    try:
        wallet_min_order_amount = int(
            get_setting_num("wallet_min_order_amount_nt", 0)
        )
    except Exception:
        wallet_min_order_amount = 0

    free_shipping_diff = (
        0.0 if total >= free_shipping_threshold
        else (free_shipping_threshold - total)
    )

    # ---- 折扣碼（若 session 有暫存，依目前 subtotal 再次檢核並計算折抵）----
    discount = session.get('cart_discount')
    discount_deduct = 0.0
    if discount:
        ok, msg, info = validate_discount_for_cart(discount.get('code'), total)
        if ok:
            discount = info                      # 更新顯示資訊（可能有新小計）
            discount_deduct = float(info['amount'])
        else:
            flash(msg)                           # 例如不達門檻/逾期
            session.pop('cart_discount', None)
            discount = None

    # 應付金額（不得為負）
    final_total = max(total + shipping_fee - discount_deduct, 0)

    # 會員顯示名稱（優先 name，否則 username、account、email）
    member_name = None
    if session.get("member_id"):
        mres = (
            supabase.table("members")
            .select("name, username, account, email")
            .eq("id", session["member_id"])
            .single()
            .execute()
        )
        m = mres.data or {}
        member_name = (
            m.get("name")
            or m.get("username")
            or m.get("account")
            or m.get("email")
        )

    # ============================================================
    # ==== 加購推薦（upsell）：若「尚未達免運」就挑商品推薦 ====
    # 不依賴 is_active/stock 欄位（避免不存在），全部使用 4 空白縮排
    # ============================================================
    upsell_products = []
    remain_for_upsell = max(0.0, (free_shipping_threshold or 0.0) - total)

    if remain_for_upsell > 0:
        try:
            cart_ids = {str(p.get('id')) for p in products if p.get('id')}

            # 只選必定存在的欄位，避免 42703
            res = (
                supabase.table('products')
                .select('id,name,price,discount_price,image,images,product_type')
                .limit(60)
                .execute()
            )
            rows = res.data or []

            def eff_price(r):
                p1 = r.get('discount_price') or r.get('price') or 0
                try:
                    return float(p1)
                except Exception:
                    return 0.0

            cand = []
            for r in rows:
                # 排除：已在購物車
                if str(r.get('id')) in cart_ids:
                    continue
                # 不想推薦套組就保留；若要推薦套組，註解下一段
                if r.get('product_type') == 'bundle':
                    continue
                # 價格必須 > 0
                if eff_price(r) <= 0:
                    continue

                # 若表中其實有 is_active/stock，可選擇性過濾（鍵不存在就略過）
                ia = r.get('is_active')
                if ia is False:
                    continue
                st = r.get('stock')
                try:
                    if st is not None and float(st) <= 0:
                        continue
                except Exception:
                    pass

                cand.append(r)

            # 依價格由小到大（最小金額優先）
            cand.sort(key=lambda r: eff_price(r))

            upsell_products = cand[:6]

        except Exception as e:
            print('[upsell] error:', e)

        # === 立即查詢購物金餘額（以 wallet_credits 明細加總） ===
    wallet_balance_cents = 0
    mid = session.get("member_id")
    if mid:
        try:
            r = (supabase.table("wallet_credits")
                 .select("amount_cents")
                 .eq("member_id", mid)
                 .execute())
            wallet_balance_cents = max(
    0,
    sum(int(x.get("amount_cents") or 0) for x in (r.data or []))
)
        except Exception:
            current_app.logger.exception("[cart] load wallet balance failed")
            wallet_balance_cents = 0


    return render_template(
        "cart.html",
        products=products,
        total=total,
        shipping_fee=shipping_fee,
        final_total=final_total,
        free_shipping_threshold=free_shipping_threshold,
        free_shipping_diff=free_shipping_diff,
        discount=discount,
        discount_deduct=discount_deduct,
        member_name=member_name,
        upsell_products=upsell_products,   # ← 帶到模板
        wallet_balance_cents=wallet_balance_cents,  # ← 新增：提供模板即時餘額
        wallet_min_order_amount=wallet_min_order_amount,
    )


# 以台灣時間解讀開始/到期；購物車驗證也用台灣時間
def _parse_tw_local(ts: str):
    """
    把資料庫回來的時間字串（可能是 '2025-08-24T08:00:00+00:00' 或 '2025-08-24T08:00'）
    統一「以台灣時間」解讀，回傳 tz-aware 的台灣時間 datetime。
    """
    if not ts:
        return None
    s = str(ts).replace("Z", "")
    base = s[:16]  # 只取到分鐘，'YYYY-MM-DDTHH:MM'
    try:
        dt = datetime.strptime(base, "%Y-%m-%dT%H:%M")
    except ValueError:
        base = base.replace("T", " ")
        dt = datetime.strptime(base, "%Y-%m-%d %H:%M")
    return TW.localize(dt)

def validate_discount_for_cart(code: str, subtotal: float):
    """
    驗證折扣碼是否可在購物車使用（以台灣時間判斷有效期）。
    回傳 (ok:bool, msg:str, info:dict|None)
    """
    if not code:
        return False, "請輸入折扣碼", None

    code = code.strip().upper()
    try:
        res = supabase.table("discounts").select("*").eq("code", code).eq("is_active", True).single().execute()
        d = res.data
    except Exception:
        d = None

    if not d:
        return False, "折扣碼不存在或未啟用", None

    now_tw = datetime.now(TW)
    start_at = _parse_tw_local(d.get("start_at"))
    expires_at = _parse_tw_local(d.get("expires_at"))
    if start_at and now_tw < start_at:
        return False, "折扣碼尚未開始", None
    if expires_at and now_tw > expires_at:
        return False, "折扣碼已逾期", None

    min_amt = float(d.get("min_order_amt") or 0)
    if subtotal < min_amt:
        return False, f"未達此折扣碼最低消費 ${int(min_amt)}", None

    dtype = d.get("type")
    val = float(d.get("value") or 0)
    if dtype == "percent":
        val = max(0.0, min(100.0, val))
        amount = round(subtotal * (val / 100.0))
    else:
        amount = min(round(val), round(subtotal))

    info = {
        "code": code,
        "type": dtype,
        "value": val,
        "min_order_amt": min_amt,
        "amount": float(amount),
    }
    return True, "折扣碼已套用", info

# 購物車：更新寄送資訊（AJAX）
@app.post("/cart/address")
def cart_address_update():
    # 需要會員已登入
    member_id = session.get("member_id")
    if not member_id:
        return jsonify({"ok": False, "error": "not_logged_in"}), 401

    data = request.get_json(silent=True) or request.form
    name    = (data.get("name") or "").strip()
    phone   = (data.get("phone") or "").strip()
    address = (data.get("address") or "").strip()
    save_profile = str(data.get("save_profile") or "").lower() in {"1","true","yes","on"}

    if not name or not phone or not address:
        return jsonify({"ok": False, "error": "missing_fields"}), 400

    # 1) 先把這次結帳要用的寄送資訊放進 session（只影響本次訂單）
    session["checkout_address"] = {"name": name, "phone": phone, "address": address}

    # 2) 若勾選同步更新，寫回 members 資料表
    if save_profile:
        try:
            supabase.table("members").update({
                "name": name,
                "phone": phone,
                "address": address
            }).eq("id", member_id).execute()
        except Exception as e:
            app.logger.error(f"[cart_address_update] update member error: {e}")

    return jsonify({"ok": True})


# 結帳
@app.route('/checkout', methods=['POST'])
def checkout():
    if 'member_id' not in session:
        flash("請先登入會員才能結帳")
        return redirect('/cart')

    cart_items = session.get('cart', [])
    if not cart_items:
        flash("購物車是空的")
        return redirect('/cart')

    member_id = session['member_id']

    # === 會員/寄送資料（優先採用購物車裡暫存的覆蓋地址） ===
    prof_res = (
        supabase.table("members")
        .select("name, phone, address")
        .eq("id", member_id)
        .single()
        .execute()
    )
    prof = prof_res.data or {}
    ship = session.get("checkout_address") or {}

    receiver_name  = (ship.get("name")    or prof.get("name")    or "").strip()
    receiver_phone = (ship.get("phone")   or prof.get("phone")   or "").strip()
    receiver_addr  = (ship.get("address") or prof.get("address") or "").strip()

    if not (receiver_name and receiver_phone and receiver_addr):
        session['incomplete_profile'] = True
        flash("請先填寫完整的收件資訊（姓名、電話、地址）再進行結帳")
        return redirect('/cart')

    # 1) 組商品明細 + 算小計（以加入購物車時記錄的價格為主）
    total = 0.0
    items = []
    for item in cart_items:
        pid = item.get('product_id')
        if not pid:
            continue
        res = supabase.table("products").select("id,name").eq("id", pid).single().execute()
        product = res.data or {}

        item_price = float(
            item.get('price')
            or item.get('discount_price')
            or product.get('discount_price')
            or product.get('price')
            or 0
        )
        qty = int(item.get('qty', 1))
        subtotal = item_price * qty
        total += subtotal

        items.append({
            'product_id': str(pid),
            'product_name': product.get('name') or item.get('name', ''),
            'qty': qty,
            'price': item_price,
            'subtotal': subtotal,
            'option': item.get('option', '')
        })

    # 2) 運費
    free_shipping_threshold, default_shipping_fee = get_shipping_rules()
    shipping_fee = 0.0 if total >= free_shipping_threshold else float(default_shipping_fee)

    # 3) 折扣碼
    discount = session.get('cart_discount')
    discount_code = None
    discount_amount = 0.0
    if discount:
        ok, msg, info = validate_discount_for_cart(discount.get('code'), total)
        if ok:
            discount_code = info['code']
            discount_amount = float(info['amount'])
        else:
            flash(msg)
            session.pop('cart_discount', None)

    # 4) 應付金額（不得為負）→ 統一轉整數入庫
    final_total = max(total + shipping_fee - discount_amount, 0)
    total_i           = _money(total)
    shipping_fee_i    = _money(shipping_fee)
    discount_amount_i = _money(discount_amount)
    final_total_i     = max(total_i + shipping_fee_i - discount_amount_i, 0)

    # 4.1 使用者此次在畫面上選的「意圖付款方式」(可有可無)
    intended = (request.form.get("payment_method") or request.form.get("method") or "").lower()
    ALLOWED_METHODS = {"linepay", "ecpay", "transfer", "atm", "bank", "bank_transfer"}
    if intended not in ALLOWED_METHODS:
        intended = None

    # 4.2 使用購物金（元）=> 轉分；上限=使用者輸入、餘額、此次應付
    try:
        wallet_req_yuan = int(float(request.form.get("wallet_amount") or 0))
    except Exception:
        wallet_req_yuan = 0
    wallet_req_yuan = max(wallet_req_yuan, 0)


    # === 購物金最低消費金額限制 ===
    cfg = _wallet_settings()
    min_order_amount_nt = float(cfg.get("wallet_min_order_amount_nt") or 0)

    # total_i 是「商品小計（元，不含運費、折扣）」
    if wallet_req_yuan > 0 and min_order_amount_nt > 0:
        if total_i < min_order_amount_nt:
            flash(f"購物金需滿 {int(min_order_amount_nt)} 元才可使用")
            return redirect("/cart")


    # 目前錢包餘額（分）— 只用 credits 明細計算（並保底 0）
    try:
        sres = (
            supabase.table("wallet_credits")
            .select("amount_cents,expires_at")
            .eq("member_id", member_id)
            .execute()
        )
        rows = sres.data or []
        balance_cents = max(_calc_available_wallet_cents(rows), 0)
    except Exception:
        balance_cents = 0

    req_cents = wallet_req_yuan * 100
    final_total_cents = int(final_total_i) * 100
    used_wallet_cents = min(req_cents, balance_cents, final_total_cents)
    used_wallet_cents = max(used_wallet_cents, 0)
    wallet_used_yuan = used_wallet_cents // 100

    # 扣完錢包後的訂單總金額（元）
    final_total_i_after_wallet = max(final_total_i - wallet_used_yuan, 0)

    # 5) 建立訂單
    from pytz import timezone
    from datetime import datetime
    tw = timezone("Asia/Taipei")
    merchant_trade_no = generate_merchant_trade_no()
    created_at = datetime.now(tw).isoformat()

    order_data = {
        'member_id': member_id,
        'total_amount':   final_total_i_after_wallet,   # ✅ 已扣完購物金
        'shipping_fee':   shipping_fee_i,
        'discount_code':  discount_code,
        'discount_amount': discount_amount_i,
        'status': 'pending',
        'created_at': created_at,
        'MerchantTradeNo': merchant_trade_no,
        'intended_payment_method': intended,
        'receiver_name': receiver_name,
        'receiver_phone': receiver_phone,
        'receiver_address': receiver_addr
    }
    result = supabase.table('orders').insert(order_data).execute()
    order_id = result.data[0]['id']

# ===== LINE 新訂單通知（checkout）=====

    try:
        send_line_order_notify(
            {
                "order_no": merchant_trade_no,
                "name": receiver_name,
                "phone": receiver_phone,
                "total": final_total_i_after_wallet
            },
            event_type="new"
        )
    except Exception as e:
        app.logger.error(f"[LINE notify failed] {e}")

    # 6) 寫入每筆商品明細
    from uuid import uuid4
    for it in items:
        it['id'] = str(uuid4())
        it['order_id'] = order_id
        it['option'] = it.get('option', '')
    supabase.table('order_items').insert(items).execute()
    # 6.1 扣庫存
    for it in items:
        pid = it.get("product_id")
        qty = int(it.get("qty") or it.get("quantity") or 0)
        if not pid or qty <= 0:
            continue
        try:
            cur = (
                supabase.table("products")
                .select("stock")
                .eq("id", pid)
                .single()
                .execute()
                .data
                or {}
            )
            cur_stock = int(cur.get("stock") or 0)
            new_stock = max(0, cur_stock - qty)
            supabase.table("products").update({"stock": new_stock}).eq("id", pid).execute()
        except Exception as e:
            app.logger.error(f"[checkout stock deduct] pid={pid} qty={qty} error={e}")

    # 6.2 若有使用購物金 → 寫入 wallet_credits（分，負數），並刷新 session / balances
    if used_wallet_cents > 0:
        try:
            # 防呆：避免同張訂單重複扣（不同訂單則可各自扣）
            exists = (
                supabase.table("wallet_credits")
                .select("id")
                .eq("reason", "order_checkout")
                .eq("related_order_id", order_id)
                .limit(1)
                .execute()
            ).data
            if not exists:
                supabase.table("wallet_credits").insert({
                    "member_id": member_id,
                    "amount_cents": -used_wallet_cents,  # 負數代表扣款（分）
                    "reason": "order_checkout",
                    "related_order_id": order_id,
                    "note": f"已使用於訂單 #{order_id}",
                }).execute()

                # ✅ 同步更新 wallet_balances（保底 0）
                try:
                    curb = (
                        supabase.table("wallet_balances")
                        .select("balance_cents")
                        .eq("member_id", member_id)
                        .single()
                        .execute()
                        .data or {}
                    )
                    cur_val = int(curb.get("balance_cents") or 0)
                    new_val = max(0, cur_val - used_wallet_cents)
                    supabase.table("wallet_balances").upsert({
                        "member_id": member_id,
                        "balance_cents": new_val
                    }, returning="minimal").execute()
                except Exception:
                    pass

                # 更新 session 徽章（保底 0）
                try:
                    session['wallet_balance_cents'] = max(
                        int(session.get('wallet_balance_cents') or 0) - used_wallet_cents, 0
                    )
                except Exception:
                    pass
        except Exception:
            current_app.logger.exception('[wallet] deduct on checkout failed')

    # 7) 成功後才累計折扣使用次數
    if discount_code:
        try:
            d = (
                supabase.table('discounts')
                .select('used_count')
                .eq('code', discount_code)
                .single()
                .execute()
                .data
                or {}
            )
            used = int(d.get('used_count') or 0) + 1
            supabase.table('discounts').update({'used_count': used}).eq('code', discount_code).execute()
        except Exception:
            pass

    # 8) 清空購物車與暫存
    session['cart'] = []
    session.pop('cart_discount', None)
    session['current_trade_no'] = merchant_trade_no
    session.pop('checkout_address', None)

    # 9) 導向選擇付款頁
    flash("訂單已建立，請選擇付款方式", "success")
    return redirect(f"/choose-payment?order_id={order_id}")



@app.route('/choose-payment')
def choose_payment():
    if 'current_trade_no' not in session:
        return redirect('/cart')

    trade_no = session['current_trade_no']
    res = supabase.table("orders").select("*").eq("MerchantTradeNo", trade_no).execute()

    if not res.data:
        return "找不到訂單", 404

    order = res.data[0]
    return render_template("choose_payment.html", order=order)

# === LINE Pay 金額/幣別 helper（缺它會造成 NameError）===
def _order_amount_currency(order):
    """
    從 orders 取實際應付金額與幣別。
    - total_amount：應為數字字串或數字；TWD 必須為整數（LINE Pay 規定）。
    - currency：預設 TWD，統一轉大寫。
    """
    raw = order.get("total_amount", 0)
    try:
        amt = int(round(float(raw)))
    except (ValueError, TypeError):
        raise ValueError(f"無效的 total_amount: {raw!r}")

    if amt <= 0:
        raise ValueError("LINE Pay 金額為 0，請檢查 orders.total_amount 寫入流程")

    currency = (order.get("currency") or "TWD").upper()
    return amt, currency

 #line pay結帳完成回傳
# line pay 結帳完成「伺服器到伺服器」通知（需在 LINE Pay 後台設定為 https://你的網域/linepay/notify）
@app.route("/linepay/notify", methods=["POST"])
def linepay_notify():
    """
    LINE Pay v3 notify：
    - 先驗簽 (X-LINE-Authorization / Nonce)
    - 優先用 transactionId 對單（orders.lp_transaction_id）
    - 找不到再依序用 orderId 比對：
        1) orders.order_no
        2) orders.MerchantTradeNo
        3) 舊制 "LP-<id>" 解析出數字 id
    - 冪等：已 paid 直接回 OK
    - 以 /v3/payments/{tx}/confirm 最終確認，成功才標記 paid
    """
    # 1) 原始資料與驗簽
    raw = request.get_data(as_text=True)
    nonce = request.headers.get("X-LINE-Authorization-Nonce", "")
    auth  = request.headers.get("X-LINE-Authorization", "")
    path  = request.path  # 必須為 "/linepay/notify"

    msg  = (LINE_PAY_CHANNEL_SECRET + path + raw + nonce).encode("utf-8")
    calc = base64.b64encode(
        hmac.new(LINE_PAY_CHANNEL_SECRET.encode("utf-8"), msg, hashlib.sha256).digest()
    ).decode("utf-8")
    if not auth or not hmac.compare_digest(auth, calc):
        app.logger.warning("[LP][notify] signature mismatch")
        return "signature mismatch", 401

    # 2) 解析 JSON
    try:
        js = json.loads(raw)
    except Exception:
        app.logger.exception("[LP][notify] bad json")
        return "bad json", 400

    order_tag = str(js.get("orderId") or "")
    tx        = (js.get("transactionId") or "").strip()
    status    = js.get("transactionStatus")  # 可能為 SUCCESS/AUTHORIZED 等（僅參考）

    if not tx:
        return "missing transactionId", 400

    # 3) 對單：transactionId → order
    order = None
    try:
        res = supabase.table("orders").select("*").eq("lp_transaction_id", tx).single().execute()
        order = res.data
    except Exception:
        order = None

    # 3-1) 相容：用 orderId 直接比對 order_no
    if not order and order_tag:
        try:
            res = supabase.table("orders").select("*").eq("order_no", order_tag).single().execute()
            order = res.data
        except Exception:
            order = None

    # 3-2) 相容：用 orderId 比對 MerchantTradeNo
    if not order and order_tag:
        try:
            res = supabase.table("orders").select("*").eq("MerchantTradeNo", order_tag).single().execute()
            order = res.data
        except Exception:
            order = None

    # 3-3) 最後相容：舊制 LP-<id>
    if not order and order_tag:
        m = re.match(r"LP-(\d+)$", order_tag)
        if m:
            legacy_id = int(m.group(1))
            try:
                res = supabase.table("orders").select("*").eq("id", legacy_id).single().execute()
                order = res.data
            except Exception:
                order = None

    if not order:
        app.logger.warning("[LP][notify] order not found; orderId=%s, tx=%s", order_tag, tx)
        return "order not found", 404

    order_id = order["id"]

    # 4) 冪等處理：已付款就直接回 OK
    if (order.get("payment_status") or "").lower() == "paid":
        return "OK", 200

    # 5) 以 Confirm API 最終確認
    amount, currency = _order_amount_currency(order)
    confirm_body = {"amount": amount, "currency": currency}
    confirm_path = f"/v3/payments/{tx}/confirm"
    payload = json.dumps(confirm_body, separators=(",", ":"))
    headers = _lp_signature_headers(confirm_path, payload, method="POST")

    try:
        r = requests.post(f"{LINE_PAY_BASE}{confirm_path}", headers=headers, data=payload, timeout=15)
        data = r.json()
    except Exception as e:
        app.logger.exception("[LP][notify] confirm request error")
        data = {"http_status": getattr(r, "status_code", None), "error": str(e)}

    if data.get("returnCode") == "0000":
        # 成功：標記付款完成（也一併寫入 lp_transaction_id，便於之後用 tx 查單）
        supabase.table("orders").update({
            "payment_status": "paid",
            "paid_trade_no": str(tx),
            "lp_transaction_id": str(tx),
            "payment_method": "linepay",
            "paid_at": datetime.now(TW).isoformat()
        }).eq("id", order_id).execute()
        return "OK", 200
    else:
        # 失敗：記錄錯誤詳細以便之後人工或排程重試
        supabase.table("orders").update({
            "payment_status": "pending_confirm_failed",
            "lp_transaction_id": str(tx),
            "lp_confirm_error": json.dumps(data, ensure_ascii=False)[:8000]
        }).eq("id", order_id).execute()
        app.logger.warning("[LP][notify] confirm failed: %s", data)
        return "NG", 400
    
# 判斷用戶選的付款方式
@app.route("/process_payment", methods=["POST"])
def process_payment():
    # 0) 取得表單 & session
    form_order_id = request.form.get("order_id")
    method = request.form.get("method")  # "linepay" / "credit" / "bank"
    is_repay = request.form.get("is_repay") == "1"
    session_order_id = session.get("pending_order_id")

    # 1) 決定 order_id（表單優先，其次 session）
    order_id = form_order_id or session_order_id
    if not order_id:
        flash("找不到待處理的訂單。", "error")
        return redirect("/cart")

    if not method:
        flash("請選擇付款方式。", "error")
        return redirect("/choose-payment")

    # 2) 讀取訂單
    try:
        order_res = (
            supabase.table("orders")
            .select("*")
            .eq("id", order_id)
            .single()
            .execute()
        )
        order = order_res.data or None
    except Exception:
        order = None

    if not order:
        return "找不到訂單", 404

    # 3) 解析 member_id：以訂單上的為主，否則用 session
    current_member_id = session.get("member_id")
    member_id = order.get("member_id") or current_member_id

    # 4) 權限檢查：避免不同會員操作他人訂單
    if order.get("member_id") and str(order["member_id"]) != str(current_member_id):
        flash("沒有權限操作此訂單。", "error")
        return redirect("/cart")

    # 5) 若訂單尚未綁會員、但目前有人登入 → 自動綁定
    if not order.get("member_id") and current_member_id:
        try:
            supabase.table("orders").update({"member_id": current_member_id}).eq("id", order_id).execute()
            order["member_id"] = current_member_id  # 同步本地變數，後續用得到
            member_id = current_member_id
        except Exception as e:
            app.logger.warning(f"[process_payment] 綁定 member_id 失敗：order_id={order_id}, err={e}")

    # 6) 會員資料完整性檢查（必須在 member_id 決定之後）
    if not member_id:
        session["incomplete_profile"] = True
        flash("請先登入並完整填寫會員資料再進行結帳。", "error")
        return redirect("/login?next=cart")

    try:
        prof_res = (
            supabase.table("members")
            .select("name, phone, address")
            .eq("id", member_id)
            .single()
            .execute()
        )
        prof = prof_res.data or {}
    except Exception:
        prof = {}

    if not (prof.get("name") and prof.get("phone") and prof.get("address")):
        session["incomplete_profile"] = True  # 你前端本來就有使用這個 flag
        flash("請先完整填寫會員資料（姓名、電話、地址）再進行結帳", "error")
        return redirect("/cart")
    
    # 6-1) 組 LINE 推播用訂單資料（此時 order / prof 都已確認存在）
    line_order_payload = {
        "order_no": order.get("order_no") or f"#{order['id']}",
        "name": prof.get("name"),
        "phone": prof.get("phone"),
        "total": order.get("total")
    }

    # 7) 依付款方式分流
    if method == "linepay":
        # 7-1) 金額／幣別（TWD 需整數）
        amount, currency = _order_amount_currency(order)

        # 7-2) 組請求 body
        body = {
            "amount": amount,
            "currency": currency,
            "orderId": str(order.get("order_no") or order.get("MerchantTradeNo") or f"LP-{order['id']}"),
            "packages": [{
                "id": "pkg-1",
                "amount": amount,
                "name": "HERSET 訂單",
                "products": [{
                    "name": f"訂單 {order.get('order_no') or order.get('MerchantTradeNo') or ('#' + str(order['id']))} 總額",
                    "quantity": 1,
                    "price": amount
                }]
            }],
            "redirectUrls": {
                "confirmUrl": f"{SITE_BASE_URL}/linepay/confirm?order_id={order['id']}",
                "cancelUrl": f"{SITE_BASE_URL}/payment_cancel?order_id={order['id']}"
            }
        }

        api_path = "/v3/payments/request"
        payload = json.dumps(body, separators=(",", ":"))  # 簽名與送出都用同一份
        headers = _lp_signature_headers(api_path, payload, method="POST")

        # 7-3) 呼叫 LINE Pay
        r = requests.post(f"{LINE_PAY_BASE}{api_path}", headers=headers, data=payload, timeout=15)
        try:
            data = r.json()
        except ValueError:
            data = {"http_status": r.status_code, "text": r.text[:1000]}

        if data.get("returnCode") == "0000":
            info = data.get("info", {})
            payment_url = info.get("paymentUrl", {}).get("web")
            transaction_id = info.get("transactionId")

            # 7-4) 訂單狀態更新
            supabase.table("orders").update({
                "payment_method": "linepay",
                "payment_status": "pending",
                "lp_transaction_id": str(transaction_id) if transaction_id else None
            }).eq("id", order["id"]).execute()


            return redirect(payment_url)
        else:
            supabase.table("orders").update({
                "payment_status": "failed",
                "lp_error": json.dumps(data, ensure_ascii=False)
            }).eq("id", order["id"]).execute()
            return f"LINE Pay 建立失敗：{data}", 400

    elif method == "bank":


        # 顯示轉帳資訊頁
        return render_template("bank_transfer.html", order=order)

    elif method == "credit":
    # 綠界刷卡
        new_trade_no = generate_merchant_trade_no()

    # ⭐【關鍵】先把交易編號寫進 orders
        supabase.table("orders").update({
            "paid_trade_no": new_trade_no,
            "payment_method": "credit",
            "payment_status": "pending"
        }).eq("id", order["id"]).execute()

        html = generate_ecpay_form(order, trade_no=new_trade_no)
        return Response(html, content_type="text/html; charset=utf-8")

    else:
         return "未知付款方式", 400

# Linepay 付款成功後 confirm
@app.route("/linepay/confirm")
def linepay_confirm():
    transaction_id = request.args.get("transactionId", "")
    order_id = request.args.get("order_id", "")
    if not order_id:
        return "參數不足：缺少 order_id", 400

    res = supabase.table("orders").select("*").eq("id", order_id).single().execute()
    order = res.data
    if not order:
        return "找不到訂單", 404

    # 已付款 → 冪等短路
    if order.get("payment_status") == "paid":
        return redirect("/thank-you")

    if not transaction_id:
        transaction_id = (order.get("lp_transaction_id") or "").strip()
    if not transaction_id:
        return "缺少 transactionId", 400

    amount, currency = _order_amount_currency(order)
    confirm_body = {"amount": amount, "currency": currency}
    confirm_path = f"/v3/payments/{transaction_id}/confirm"
    payload = json.dumps(confirm_body, separators=(",", ":"))
    headers = _lp_signature_headers(confirm_path, payload, method="POST")

    r = requests.post(f"{LINE_PAY_BASE}{confirm_path}", headers=headers, data=payload, timeout=15)
    try:
        data = r.json()
    except ValueError:
        data = {"http_status": r.status_code, "text": r.text[:1000]}

    if data.get("returnCode") == "0000":
    # 1) 更新訂單狀態
        supabase.table("orders").update({
            "payment_status": "paid",
            "paid_trade_no": str(transaction_id)
        }).eq("id", order_id).execute()

        # 2) 推播「已付款完成」到 LINE（只在首次成功時）
        try:
            send_line_order_notify({
                "order_no": order.get("MerchantTradeNo") or f"#{order_id}",
                "name": order.get("receiver_name"),
                "phone": order.get("receiver_phone"),
                "total": order.get("total_amount")
            }, event_type="paid")
        except Exception as e:
            app.logger.error(f"[LINE paid notify failed] order_id={order_id}, err={e}")

        # 3) 導頁
        return redirect("/thank-you")

    else:
        supabase.table("orders").update({
            "payment_status": "pending_confirm_failed",
            "lp_confirm_error": json.dumps(data, ensure_ascii=False)
        }).eq("id", order_id).execute()
        return redirect("/cart")
     
# LINE Pay 取消返回（直接回首頁；不再轉 /order/cancel/<id>）
@app.route("/payment_cancel")
def linepay_cancel():
    # LINE Pay 會帶回的參數
    mtno  = request.args.get("orderId") or request.args.get("merchantTradeNo")  # 你的 MerchantTradeNo
    oid   = request.args.get("order_id")  # 你舊版自己帶的數字 id
    txnid = request.args.get("transactionId")

    # 可選：把訂單標記回未付款 / 待處理（相容以 id 或 MerchantTradeNo 查）
    try:
        target = mtno or oid
        if target:
            q = (
                supabase.table("orders")
                .select("id")
                .or_(f"id.eq.{target},MerchantTradeNo.eq.{target}")
                .limit(1)
                .execute()
            )
            row = (q.data or [None])[0]
            if row:
                supabase.table("orders").update({
                    "payment_status": "unpaid",
                    "status": "pending",
                    "payment_method": None,
                    "intended_payment_method": None,
                    "last_payment_error": "linepay_cancelled",
                    "linepay_transaction_id": txnid,
                }).eq("id", row["id"]).execute()
    except Exception as e:
        app.logger.warning(f"[payment_cancel] skip update: {e}")

    flash("您已取消付款，訂單尚未完成。可至『歷史訂單』重新付款，或改用其他方式。")
    return redirect("/")

@app.route("/order/cancel/<path:_any>")
def order_cancel_legacy(_any):
    flash("您已取消付款。")
    return redirect("/")


# 取消訂單：僅允許本人、未出貨的訂單；若有使用購物金，退回
@app.route("/order/cancel/<int:order_id>", methods=["POST"])
def order_cancel(order_id):
    if "member_id" not in session:
        return redirect("/login")
    member_id = session["member_id"]

    # 取訂單
    o = (
        supabase.table("orders")
        .select("id, member_id, status, payment_status")
        .eq("id", order_id)
        .single()
        .execute()
        .data or {}
    )
    if not o or str(o.get("member_id")) != str(member_id):
        flash("找不到訂單或無權限")
        return redirect(request.referrer or "/order-history")

    # 已付款不可取消
    if o.get("payment_status") == "paid":
        flash("此訂單已付款完成，無法取消")
        return redirect(request.referrer or "/order-history")

    # 已出貨不可取消
    if o.get("status") == "shipped":
        flash("已出貨訂單不可取消")
        return redirect(request.referrer or "/order-history")

    # 已取消直接返回
    if o.get("status") == "cancelled":
        flash("此訂單已取消")
        return redirect(request.referrer or "/order-history")

    # ✅ 將訂單標記為取消（會員）
    from datetime import datetime
    try:
        cancelled_at_iso = datetime.now(TW).isoformat()  # 若你的程式有定義 TW=Asia/Taipei
    except NameError:
        cancelled_at_iso = datetime.now().isoformat()

    supabase.table("orders").update({
        "status": "cancelled",
        "cancelled_by": "member",
        "cancelled_at": cancelled_at_iso
    }).eq("id", order_id).execute()

    # 若該訂單曾扣過購物金 → 回補
    try:
        used_rows = (
            supabase.table("wallet_credits")
            .select("amount_cents")
            .eq("member_id", member_id)
            .eq("reason", "order_checkout")
            .eq("related_order_id", order_id)
            .execute()
            .data or []
        )
        # 把該訂單扣過的負數累計回補為正數
        used_cents = -sum(int(r.get("amount_cents") or 0)
                          for r in used_rows
                          if int(r.get("amount_cents") or 0) < 0)
        if used_cents > 0:
            supabase.table("wallet_credits").insert({
                "member_id": member_id,
                "amount_cents": used_cents,
                "reason": "refund",
                "related_order_id": order_id,
                "note": "取消訂單退回"
            }).execute()

            # 同步更新 balances（保底 0）
            try:
                cur = (
                    supabase.table("wallet_balances")
                    .select("balance_cents")
                    .eq("member_id", member_id)
                    .single()
                    .execute()
                    .data or {}
                )
                new_val = max(0, int(cur.get("balance_cents") or 0) + used_cents)
                supabase.table("wallet_balances").upsert({
                    "member_id": member_id,
                    "balance_cents": new_val
                }, returning="minimal").execute()
            except Exception:
                pass

            # 更新 session 徽章
            try:
                session["wallet_balance_cents"] = max(
                    int(session.get("wallet_balance_cents") or 0) + used_cents, 0)
            except Exception:
                pass
    except Exception:
        current_app.logger.exception("[order_cancel] refund wallet failed")

    flash("訂單已取消")
    # 回到歷史訂單頁
    return redirect("/order-history")



# 歷史訂單重新付款
@app.route("/repay/<merchant_trade_no>")
def repay_order(merchant_trade_no):
    # 查原始訂單
    order_result = supabase.table("orders").select("*").eq("MerchantTradeNo", merchant_trade_no).execute()
    if not order_result.data:
        return "找不到對應的訂單", 404

    order = order_result.data[0]

# ❗已取消的訂單不可重新付款
    if (order.get("status") or "").lower() == "cancelled":
        flash("此訂單已取消，無法重新付款。", "error")
        return redirect("/order-history")

    # 顯示付款方式選擇畫面
    return render_template("choose_payment.html", order=order, is_repay=True)


# （可選）後端備援查詢：檢查是否可確認，若可用 Confirm API 自動完成
@app.route("/internal/linepay/check_and_confirm")
def linepay_check_and_confirm():
    order_id = request.args.get("order_id", "")
    if not order_id:
        return {"ok": False, "msg": "missing order_id"}, 400

    # 取出 transactionId
    res = supabase.table("orders").select("*").eq("id", order_id).single().execute()
    order = res.data or {}
    tx = (order.get("lp_transaction_id") or "").strip()
    if not tx:
        return {"ok": False, "msg": "no transactionId"}, 400
    if order.get("payment_status") == "paid":
        return {"ok": True, "msg": "already paid"}

    # 1) Check payment request status（未使用導轉時建議；導轉遺失時也可當備援）
    api_path = f"/v3/payments/requests/{tx}/check"
    # GET 沒有 body，但簽名要對「查詢字串」；這裡無 query → 空字串
    headers = _lp_signature_headers(api_path, "", method="GET")
    r = requests.get(f"{LINE_PAY_BASE}{api_path}", headers=headers, timeout=15)
    js = r.json()
    # 依回應判定是否可以進行 confirm（以官方回傳碼為準）
    # 確認條件：已完成 LINE Pay 認證，且可執行 confirm
    if js.get("returnCode") == "0000":
        # 2) 可以 confirm → 立即打 Confirm API
        amount, currency = _order_amount_currency(order)
        confirm_body = {"amount": amount, "currency": currency}
        confirm_path = f"/v3/payments/{tx}/confirm"
        payload = json.dumps(confirm_body, separators=(",", ":"))
        headers2 = _lp_signature_headers(confirm_path, payload, method="POST")
        r2 = requests.post(f"{LINE_PAY_BASE}{confirm_path}", headers=headers2, data=payload, timeout=15)
        js2 = r2.json()
        if js2.get("returnCode") == "0000":
            supabase.table("orders").update({
                "payment_status": "paid",
                "paid_trade_no": str(tx)
            }).eq("id", order_id).execute()
            return {"ok": True, "msg": "paid via auto confirm"}
        return {"ok": False, "msg": f"confirm failed: {js2}"}, 400

    return {"ok": False, "msg": f"not ready: {js}"}, 400





@app.route('/thank_you')
@app.route('/thank-you')
def thank_you():
    return render_template("thank_you.html")


#後台訂單狀態修改
@app.route('/admin0363/orders/update_status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    new_status_raw = (request.form.get("status") or "").lower()

    # 後台安全檢查
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    if not new_status_raw:
        return redirect("/admin0363/dashboard?tab=orders")

    # 「未付款，取消訂單」：同時把付款狀態打回 unpaid，並記錄取消者與時間
    if new_status_raw == "cancelled_unpaid":
        from datetime import datetime
        try:
            cancelled_at_iso = datetime.now(TW).isoformat()
        except NameError:
            cancelled_at_iso = datetime.now(tw).strftime("%Y-%m-%d %H:%M:%S")

        supabase.table("orders").update({
            "status": "cancelled",
            "payment_status": "unpaid",
            "payment_method": None,
            "paid_at": None,
            "cancelled_by": "admin",
            "cancelled_at": cancelled_at_iso
        }).eq("id", order_id).execute()
        flash(f"訂單 #{order_id} 已標記為『已取消（未付款）』", "success")
        return redirect("/admin0363/dashboard?tab=orders")

    # 其他狀態：照原邏輯更新
    supabase.table("orders").update({"status": new_status_raw}).eq("id", order_id).execute()
    flash(f"訂單 #{order_id} 出貨狀態已修改", "success")
    return redirect("/admin0363/dashboard?tab=orders")



# 後台付款狀態修改（ATM/匯款人工入帳用）
@app.route('/admin0363/orders/update_payment/<int:order_id>', methods=['POST'])
def update_order_payment(order_id):
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    new_ps = (request.form.get("payment_status") or "").lower()

    # 從表單讀取可選的付款方式（可沒有；沒有就預設轉帳）
    pm_raw = (request.form.get("payment_method") or request.form.get("pm") or "").lower()
    # 正規化
    if pm_raw in ("atm", "bank", "bank_transfer"):
        pm_raw = "transfer"
    elif pm_raw not in ("transfer", "linepay", "ecpay"):
        pm_raw = None  # 未提供或不在白名單

    if new_ps == "paid":
        # 這條路通常是人工入帳，預設視為轉帳；若表單有送 linepay/ecpay 就照送的
        final_pm = pm_raw or "transfer"

        from datetime import datetime
        try:
            # 如果你專案裡已經有全域 TW，就用它；否則用本地時間或自行 import pytz
            paid_at_iso = datetime.now(TW).isoformat()  # 若沒有 TW，改成 datetime.now().isoformat()
        except NameError:
            paid_at_iso = datetime.now().isoformat()

        supabase.table("orders").update({
            "payment_status": "paid",
            "payment_method": final_pm,
            "paid_at": paid_at_iso
        }).eq("id", order_id).execute()

        human = "LINE Pay 付款" if final_pm == "linepay" else ("信用卡付款" if final_pm == "ecpay" else "轉帳付款")
        flash(f"訂單 #{order_id} 已標記為：{human}", "success")

    elif new_ps == "unpaid":
        # 退回未付款：一併清空付款方式與已付款時間
        supabase.table("orders").update({
            "payment_status": "unpaid",
            "payment_method": None,
            "paid_at": None
        }).eq("id", order_id).execute()
        flash(f"訂單 #{order_id} 付款狀態已修改為：未付款", "success")

    else:
        flash("付款狀態值不正確", "error")

    return redirect("/admin0363/dashboard?tab=orders")



# 取代整段：商品詳情（同時支援單品 & 套組）
@app.route('/product/<product_id>')
def product_detail(product_id):
    try:
        # ⚠️ 避免 .single() 遇到 0 筆/多筆直接丟 PGRST116
        res = supabase.table("products").select("*").eq("id", product_id).limit(1).execute()
        product = (res.data or [None])[0]
    except Exception as e:
        app.logger.error(f"🚨 讀取商品錯誤 id={product_id}: {e}")
        return "找不到商品", 404

    if not product:
        # 不存在 → 回 404（不要 500）
        return "找不到商品", 404
    
        # 🔻 若商品已下架，前台直接回 404（避免被看到）
    if product.get('is_hidden') is True:
        return "找不到商品", 404


    cart = session.get('cart', [])
    cart_count = sum(item.get('qty', 0) for item in cart)

    # 預設值（避免未定義）
    bundle = None
    slots = []
    pool_products = []
    slot_allowed = {}
    total_mode = False
    required_total = 0

    # 套組殼商品：採用 required_total + pool 模式
    if product.get('product_type') == 'bundle':
        try:
            bres = (
                supabase.table("bundles")
                .select("*")
                .eq("shell_product_id", product.get("id"))
                .limit(1)
                .execute()
            )
            bundle = (bres.data or [None])[0]
        except Exception as e:
            app.logger.warning(f"⚠️ 讀取套組失敗 product_id={product.get('id')}: {e}")
            bundle = None

        if bundle:
            required_total = int(bundle.get("required_total") or 0)
            total_mode = required_total > 0

            # 共用可選池
            try:
                pres = (
                    supabase.table("bundle_pool")
                    .select("product_id")
                    .eq("bundle_id", bundle["id"])
                    .execute()
                )
                pool_ids = [r["product_id"] for r in (pres.data or [])]
                if pool_ids:
                    pool_products = (
                        supabase.table("products")
                        .select("id,name,price,options,image,images")
                        .in_("id", pool_ids)
                        .eq("is_hidden", False)
                        .order("name")
                        .execute()
                        .data
                        or []
                    )
            except Exception as e:
                app.logger.warning(f"⚠️ 讀取套組可選池失敗 bundle_id={bundle.get('id')}: {e}")
                pool_products = []

    return render_template(
        "product.html",
        product=product,
        cart_count=cart_count,
        bundle=bundle,
        slots=slots,
        pool_products=pool_products,
        slot_allowed=slot_allowed,
        total_mode=total_mode,
        required_total=required_total,
        dbg_user=session.get("user")
    )

from utils import verify_check_mac_value

@app.route("/ecpay/return", methods=["POST"])
def ecpay_return():
    data = request.form.to_dict()
    app.logger.info(f"[ECPay] return data = {data}")

    trade_no = data.get("MerchantTradeNo")
    rtn_code = data.get("RtnCode")
    payment_date = data.get("PaymentDate")

    # 綠界規定：不論成功失敗都要回 1|OK
    if not trade_no or rtn_code != "1":
        return "1|OK"

    order = None

    # ======================================================
    # ① 先用 orders.paid_trade_no 找（首刷）
    # ======================================================
    try:
        res = (
            supabase.table("orders")
            .select("*")
            .eq("paid_trade_no", trade_no)
            .maybe_single()
            .execute()
        )
        order = res.data
    except Exception as e:
        app.logger.error(f"[ECPay] order lookup error (orders): {e}")

    # ======================================================
    # ② 找不到才查補刷對照表 ecpay_repay_map
    # ======================================================
    if not order:
        try:
            repay = (
                supabase.table("ecpay_repay_map")
                .select("order_id")
                .eq("new_trade_no", trade_no)
                .maybe_single()
                .execute()
            ).data

            if repay:
                order = (
                    supabase.table("orders")
                    .select("*")
                    .eq("id", repay["order_id"])
                    .maybe_single()
                    .execute()
                ).data
        except Exception as e:
            app.logger.error(f"[ECPay] repay_map lookup error: {e}")

    # ======================================================
    # ③ 還是找不到 → 記 log + 正常回應
    # ======================================================
    if not order:
        app.logger.error(f"[ECPay] order not found, trade_no={trade_no}")
        return "1|OK"

    # ======================================================
    # ④ 冪等：已付款就直接結束
    # ======================================================
    if order.get("payment_status") == "paid":
        return "1|OK"

    # ======================================================
    # ⑤ 更新訂單狀態
    # ======================================================
    supabase.table("orders").update({
        "payment_status": "paid",
        "payment_method": "credit",
        "payment_time": payment_date,
        "paid_trade_no": trade_no
    }).eq("id", order["id"]).execute()

    # ======================================================
    # ⑥ LINE 通知（沿用你 LINE Pay 那套）
    # ======================================================
    try:
        send_line_order_notify({
            "order_no": order.get("order_no") or f"#{order['id']}",
            "name": order.get("receiver_name"),
            "phone": order.get("receiver_phone"),
            "total": order.get("total_amount")
        }, event_type="paid")
    except Exception as e:
        app.logger.error(f"[ECPay] LINE notify failed: {e}")

    return "1|OK"

#讓使用者刷完卡回到網站
@app.route("/ecpay/result", methods=["POST"])
def ecpay_result():
    return redirect("/thank-you")


#重新付款處理
@app.route("/notify", methods=["POST"])
def handle_ecpay_result():
    result = request.form.to_dict()

    # Step 1: 驗證 CheckMacValue
    from utils import verify_check_mac_value
    if not verify_check_mac_value(result):
        return "Invalid CheckMacValue", 400

    merchant_trade_no = result.get("MerchantTradeNo")
    payment_date = result.get("PaymentDate")
    rtn_code = result.get("RtnCode")  # 綠界定義：1 為成功

    # Step 2: 找出對應訂單
    order = None

    # 先從 ecpay_repay_map 尋找 retry 記錄
    map_result = supabase.table("ecpay_repay_map").select("*").eq("new_trade_no", merchant_trade_no).execute()
    if map_result.data:
        order_id = map_result.data[0]['order_id']
        order_result = supabase.table("orders").select("*").eq("id", order_id).execute()
    else:
        # 沒 retry 過，直接用原始 TradeNo 查
        order_result = supabase.table("orders").select("*").eq("MerchantTradeNo", merchant_trade_no).execute()

    if not order_result.data:
        return "Order not found", 404

    order = order_result.data[0]

    # Step 3: 儲存付款紀錄（建議你在 Step 1 就先存一筆 log，也可在這邊補存）
    supabase.table("payment_log").insert({
        "merchant_trade_no": merchant_trade_no,
        "order_id": order["id"],
        "rtn_code": rtn_code,
        "rtn_msg": result.get("RtnMsg"),
        "payment_type": result.get("PaymentType"),
        "payment_date": payment_date,
        "raw_data": json.dumps(result)
    }).execute()

    # Step 4: 更新訂單狀態（只有成功才更新）
    if str(rtn_code) == "1":
        supabase.table("orders").update({
            "payment_status": "paid",
            "payment_method": "credit",
            "payment_time": payment_date,
            "paid_trade_no": merchant_trade_no
        }).eq("id", order["id"]).execute()

    # ✅ 發送 LINE 已付款完成通知
        try:
            send_line_order_notify({
                "order_no": order.get("MerchantTradeNo") or f"#{order['id']}",
                "name": order.get("receiver_name"),
                "phone": order.get("receiver_phone"),
                "total": order.get("total_amount")
            }, event_type="paid")
        except Exception as e:
            app.logger.error(
                f"[ECPay LINE notify failed] order_id={order['id']} err={e}"
            )

            # 🔻 撈該訂單所有商品項目
    item_res = supabase.table("order_items").select("*").eq("order_id", order["id"]).execute()
    items = item_res.data or []

    for item in items:
        pid = item["product_id"]
        qty = item["qty"]

        # 🔻 查目前庫存
        p_res = supabase.table("products").select("stock").eq("id", pid).single().execute()
        if p_res.data:
            current_stock = p_res.data["stock"] or 0
            new_stock = max(current_stock - qty, 0)  # 最少為 0

            # 🔻 更新庫存
            supabase.table("products").update({"stock": new_stock}).eq("id", pid).execute()


    return "1|OK"  # 綠界固定格式，代表成功處理





#封鎖 /admin 的舊路由
@app.route('/admin')
def block_admin_shortcut():
    return "404 Not Found    The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.", 403

#搜尋會員
@app.route('/admin/members')
def search_members():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    members = (supabase.table("members")
               .select("id, account, username, name, phone, email, address, note, created_at")
               .order("created_at", desc=True)
               .execute().data) or []

    for m in members:
        try:
            m['created_at'] = parser.parse(m['created_at']).astimezone(TW).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

    return render_template("admin.html",
        tab="members",
        products=[],
        orders=[],
        members=members,
        messages=[],
        product_page=1,
        product_total_pages=1,
        product_page_size=10,
        msg_page=1,
        msg_total_pages=1,
        order_page=1,
        order_total_count=0,
        new_order_alert=False,
        new_message_alert=False
    )


# 後台：刪除訂單（最高權限｜硬刪除｜已啟用 ON DELETE CASCADE）
@app.post('/admin0363/orders/delete/<int:order_id>')
def admin_delete_order(order_id):
    # 僅允許已登入的管理員
    if not session.get('admin_logged_in'):
        return redirect('/admin0363')

    # 只需刪主表；order_items 會由外鍵自動連動刪除
    supabase.table('orders').delete().eq('id', order_id).execute()

    flash('訂單已從資料庫刪除', 'success')
    return redirect('/admin0363/dashboard?tab=orders')




@app.route('/admin/new')
def new_product():
    return render_template("new_product.html")


#新增商品
@app.route('/add_product', methods=['POST'])
def add_product():
    try:
        name = request.form.get('name', '').strip()
        price_str = request.form.get('price', '0').strip()
        price = float(price_str) if price_str else 0.0

        # ✅ 優惠價
        discount_price_str = request.form.get("discount_price", "").strip()
        discount_price = float(discount_price_str) if discount_price_str else None

        stock_str = request.form.get('stock', '0').strip()
        stock = int(stock_str) if stock_str else 0
        intro = request.form.get('intro', '').strip()
        feature = request.form.get('feature', '').strip()
        spec = request.form.get('spec', '').strip()
        ingredient = request.form.get('ingredient', '').strip()
        categories = request.form.getlist('categories[]')
        tags = request.form.getlist('tags')  # ✅ 多選標籤
        options = request.form.getlist('options[]')

        # ✅ 影片連結（表單貼的）
        video_urls_from_form = [
            (u or '').strip()
            for u in request.form.getlist('video_urls[]')
            if (u or '').strip()
        ]

        # ✅ 上傳首頁主圖（單張）
        cover_image_file = request.files.get("cover_image")
        cover_url = ""
        if cover_image_file and cover_image_file.filename:
            filename = secure_filename(cover_image_file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            cover_path = f"product_images/{unique_filename}"
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                cover_image_file.save(tmp.name)
                try:
                    supabase.storage.from_("images").upload(cover_path, tmp.name)
                    cover_url = supabase.storage.from_("images").get_public_url(cover_path)
                except Exception as e:
                    print("❗️主圖上傳錯誤：", e)

        # ✅ 上傳其他圖片（多張）
        image_files = request.files.getlist("image_files")
        image_urls = []
        for file in image_files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                storage_path = f"product_images/{unique_filename}"
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    file.save(tmp.name)
                    try:
                        supabase.storage.from_("images").upload(storage_path, tmp.name)
                        url = supabase.storage.from_("images").get_public_url(storage_path)
                        image_urls.append(url)
                    except Exception as e:
                        print("❗️圖片上傳錯誤：", e)

        # ❗️沒有主圖直接擋下（維持你原本邏輯）
        if not cover_url:
            return "請上傳商品首頁主圖", 400

        # ✅ 上傳影片檔（多支）
        #    - 和圖片共用同一個 bucket：images
        #    - 存到 product_videos/ 目錄
        allowed_video_ext = {'mp4', 'webm', 'ogv', 'mov', 'm4v'}
        video_files = request.files.getlist("video_files")
        video_urls_from_upload = []
        for vf in video_files:
            if not vf or not vf.filename:
                continue
            ext = (vf.filename.rsplit('.', 1)[-1] or '').lower()
            if ext not in allowed_video_ext:
                print(f"⚠️ 略過不支援的影片格式：{vf.filename}")
                continue

            v_name = secure_filename(vf.filename)
            v_unique = f"{uuid.uuid4()}_{v_name}"
            v_path = f"product_videos/{v_unique}"
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                vf.save(tmp.name)
                try:
                    supabase.storage.from_("images").upload(v_path, tmp.name)
                    v_url = supabase.storage.from_("images").get_public_url(v_path)
                    video_urls_from_upload.append(v_url)
                except Exception as e:
                    print("❗️影片上傳錯誤：", e)

        # ✅ 合併影片清單（上傳檔＋表單連結）
        videos = video_urls_from_upload + video_urls_from_form

        # ✅ 建立商品資料（含優惠價 & 影片）
        data = {
            "name": name,
            "price": price,
            "discount_price": discount_price,
            "stock": stock,
            "image": cover_url,      # 首頁主圖
            "images": image_urls,    # 圖片清單
            "videos": videos,        # ✅ 新增：影片清單（list[str]）
            "intro": intro,
            "feature": feature,
            "spec": spec,
            "ingredient": ingredient,
            "options": options,
            "categories": categories,
            "tags": tags,
            "is_hidden": bool(request.form.get("is_hidden"))   # 🔻 新增：下架欄位
        }

        response = supabase.table("products").insert(data).execute()

        # 依你原本的錯誤處理邏輯
        if hasattr(response, 'error') and response.error:
            return f"資料寫入失敗：{response.error['message']}", 500

        return redirect('/admin0363/dashboard?tab=products')

    except Exception as e:
        print("🔥 商品新增錯誤：", e)
        traceback.print_exc()
        return f"新增商品時發生錯誤：{str(e)}", 500


#修改商品
@app.route('/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if request.method == 'POST':
        try:
            # === 基本欄位 ===
            updated = {
                "name": (request.form.get('name') or '').strip(),
                "price": float((request.form.get('price') or '0').strip()),
                "discount_price": float(request.form.get('discount_price').strip()) if request.form.get('discount_price') else None,
                "stock": int((request.form.get('stock') or '0').strip() or 0),
                "intro": (request.form.get('intro') or '').strip(),
                "feature": (request.form.get('feature') or '').strip(),
                "spec": (request.form.get('spec') or '').strip(),
                "ingredient": (request.form.get('ingredient') or '').strip(),
                "options": request.form.getlist('options[]'),
                "categories": request.form.getlist('categories[]'),
                "tags": request.form.getlist('tags'),
                "is_hidden": request.form.get("is_hidden") == "on"  # 🔻 新增：下架欄位
            }

            # === 主圖處理（單張） ===
            cover_file = request.files.get("cover_image_file")
            if cover_file and cover_file.filename:
                filename = secure_filename(cover_file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                storage_path = f"product_images/{unique_filename}"
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    cover_file.save(tmp.name)
                    try:
                        supabase.storage.from_("images").upload(storage_path, tmp.name)
                        cover_url = supabase.storage.from_("images").get_public_url(storage_path)
                        updated['image'] = cover_url
                    except Exception as e:
                        print("❗️主圖上傳錯誤：", e)
            else:
                # 沒重新上傳就沿用舊值（hidden）
                existing_cover = request.form.get("existing_cover_image")
                if existing_cover:
                    updated["image"] = existing_cover

            # === 其他圖片（多張） ===
            kept_images = request.form.getlist("existing_images[]")  # 使用者未刪除的舊圖
            image_files = request.files.getlist("image_files")       # 新增上傳
            image_urls = []
            for file in image_files:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4()}_{filename}"
                    storage_path = f"product_images/{unique_filename}"
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        file.save(tmp.name)
                        try:
                            supabase.storage.from_("images").upload(storage_path, tmp.name)
                            url = supabase.storage.from_("images").get_public_url(storage_path)
                            image_urls.append(url)
                        except Exception as e:
                            print("❗️圖片上傳錯誤：", e)

            updated['images'] = kept_images + image_urls
            if 'image' not in updated and updated['images']:
                updated['image'] = updated['images'][0]

            # === 影片處理（新增） ===
            # 1) 保留的舊影片（hidden）
            kept_videos = request.form.getlist("existing_videos[]")

            # 2) 新貼連結
            video_urls_from_form = [
                (u or '').strip()
                for u in request.form.getlist('video_urls[]')
                if (u or '').strip()
            ]

            # 3) 新上傳檔案（傳到同一個 images bucket 的 product_videos/）
            allowed_video_ext = {'mp4', 'webm', 'ogv', 'mov', 'm4v'}
            video_files = request.files.getlist("video_files")
            video_urls_from_upload = []
            for vf in video_files:
                if not vf or not vf.filename:
                    continue
                ext = (vf.filename.rsplit('.', 1)[-1] or '').lower()
                if ext not in allowed_video_ext:
                    print(f"⚠️ 略過不支援的影片格式：{vf.filename}")
                    continue
                v_name = secure_filename(vf.filename)
                v_unique = f"{uuid.uuid4()}_{v_name}"
                v_path = f"product_videos/{v_unique}"
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    vf.save(tmp.name)
                    try:
                        supabase.storage.from_("images").upload(v_path, tmp.name)
                        v_url = supabase.storage.from_("images").get_public_url(v_path)
                        video_urls_from_upload.append(v_url)
                    except Exception as e:
                        print("❗️影片上傳錯誤：", e)

            # 合併成最終 videos
            updated['videos'] = kept_videos + video_urls_from_form + video_urls_from_upload

            # === 寫回資料庫 ===
            supabase.table("products").update(updated).eq("id", product_id).execute()
            return redirect('/admin0363/dashboard?tab=products')

        except Exception as e:
            print("🔥 編輯商品錯誤：", e)
            traceback.print_exc()
            return f"編輯商品時發生錯誤：{str(e)}", 500

    else:
        # GET：載入編輯頁
        res = supabase.table("products").select("*").eq("id", product_id).single().execute()
        product = res.data
        if not product:
            return "找不到商品", 404
        return render_template("edit_product.html", product=product)




#刪除商品
@app.route('/delete/<product_id>', methods=['POST'])
def delete_product(product_id):

    supabase.table("products").delete().eq("id", product_id).execute()
    return redirect('/admin0363/dashboard')


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    # 同時支援 Form 與 JSON
    data = request.get_json(silent=True) or {}
    form = request.form

    # 小工具：先表單，再 JSON，最後 querystring 取值
    def pick(*keys, default=None):
        for k in keys:
            v = form.get(k) if form else None
            if v is None and data:
                v = data.get(k)
            if v is None:
                v = request.args.get(k)
            if v is not None:
                return v
        return default

    product_id = (pick('product_id', 'id', default='') or '').strip()  # 有些前端會傳 id
    qty_raw    = pick('qty', default=1)
    option     = (pick('option', default='') or '').strip()
    action     = (pick('action', default='') or '').strip()
    next_url   = (pick('next', default='') or '').strip()              # 讓 upsell 能導回 cart

    # 解析數量
    try:
        qty = int(qty_raw)
        if qty <= 0:
            qty = 1
    except Exception:
        qty = 1

    # 參數缺失
    if not product_id:
        if action == 'checkout' or next_url == 'cart':
            return redirect(url_for('cart'))
        return jsonify(success=False, message="缺少商品編號"), 400

    # 1) 取商品
    res = (
        supabase.table('products')
        .select('*')
        .eq('id', str(product_id))
        .single()
        .execute()
    )
    product = res.data
    if not product:
        if action == 'checkout' or next_url == 'cart':
            return redirect(url_for('cart'))
        return jsonify(success=False, message="找不到商品"), 404

        # 🔻 已下架商品不可加入購物車
    if product.get('is_hidden') is True:
        if action == 'checkout' or next_url == 'cart':
            return redirect(url_for('cart'))
        return jsonify(success=False, message="此商品目前已下架"), 400


    # ---- A) 若商品有選項但未帶 option（或帶了無效 option）：導去商品頁先選 ----
    # 相容不同欄位：options / option_values / variants(物件陣列) / 逗號字串
    def extract_options(p):
        src = None
        if isinstance(p.get('options'), list) and p['options']:
            src = p['options']
        elif isinstance(p.get('option_values'), list) and p['option_values']:
            src = p['option_values']
        elif isinstance(p.get('variants'), list) and p['variants']:
            tmp = []
            for v in p['variants']:
                nm = (v.get('name') or v.get('title') or v.get('label') or '').strip()
                if nm:
                    tmp.append(nm)
            src = tmp
        elif isinstance(p.get('options'), str) and p['options'].strip():
            import re
            src = [s.strip() for s in re.split(r'[,\n、|｜/]+', p['options']) if s.strip()]
        if not src:
            return []
        # 去重+過濾空白
        seen, out = set(), []
        for s in src:
            s = (str(s) or '').strip()
            if s and s not in seen:
                out.append(s); seen.add(s)
        return out

    candidate_options = extract_options(product)

    def _norm(s):  # 大小寫/空白不敏感比對
        return (str(s or '')).strip().lower()

    option_invalid = False

    if candidate_options:
        if not option:
            # ✅ 只有一個規格 → 自動選
            if len(candidate_options) == 1:
                option = candidate_options[0]
            else:
                option_invalid = True
        else:
            valid = {_norm(x) for x in candidate_options}
            option_invalid = (_norm(option) not in valid)

    if option_invalid:
        product_url = f"/product/{product_id}?need_option=1#options"
        wants_json = (
            request.is_json
            or 'application/json' in (request.headers.get('Accept') or '')
            or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        )
        if wants_json:
            return jsonify(
                success=False,
                requires_option=True,
                product_id=product_id,
                redirect=product_url
            ), 200
        try:
            flash("此商品需先選擇款式，再加入購物車")
        except Exception:
            pass
        return redirect(product_url)

    # ---- B) 價格計算（與你原本一致）----
    is_bundle = (product.get('product_type') == 'bundle')

    try:
        orig = float(product.get('price') or 0)          # 原價
    except Exception:
        orig = 0.0
    try:
        disc = float(product.get('discount_price') or 0) # 折扣價
    except Exception:
        disc = 0.0
    cur = disc if (disc and disc < orig) else orig       # 結帳用單價（先用單品邏輯）

    # 套組價覆蓋
    bundle_price = None
    bundle_compare = None
    if is_bundle:
        try:
            b = (
                supabase.table('bundles')
                .select('price, compare_at, shell_product_id')
                .eq('shell_product_id', str(product_id))
                .single()
                .execute()
                .data
            )
            if b:
                bp = float(b.get('price') or 0)
                bc = float(b.get('compare_at') or 0)
                if bp > 0:
                    cur = bp
                    bundle_price = bp
                if bc > 0:
                    orig = bc
                    bundle_compare = bc
        except Exception:
            pass

    # 4) 初始化購物車
    cart = session.get('cart', [])

    # 5) 相同商品+規格 -> 增量
    matched = False
    pid_str = str(product_id)
    opt_str = str(option or '')
    for item in cart:
        if str(item.get('product_id')) == pid_str and str(item.get('option') or '') == opt_str:
            try:
                item['qty'] = int(item.get('qty', 1)) + qty
            except Exception:
                item['qty'] = qty
            matched = True
            break

    # 6) 新增項目
    if not matched:
        entry = {
            'id': pid_str,
            'product_id': pid_str,
            'name': product.get('name'),
            'price': cur,                           # 小計用單價
            'original_price': orig,                 # 顯示用
            'discount_price': (disc if (disc and disc < orig) else 0),
            'image': product.get('image'),
            'images': product.get('images', []),
            'qty': qty,
            'option': opt_str,
            'product_type': product.get('product_type'),
        }
        if bundle_price is not None:
            entry['bundle_price'] = bundle_price
        if bundle_compare is not None:
            entry['bundle_compare'] = bundle_compare
        cart.append(entry)

    # 7) 寫回 session
    session['cart'] = cart
    try:
        session['cart_count'] = sum(int(x.get('qty', 1)) for x in cart)
    except Exception:
        session['cart_count'] = len(cart)
    session.modified = True

    # 8) 回應
    if action == 'checkout' or next_url == 'cart':
        return redirect(url_for('cart'))

    total_qty = session.get('cart_count', len(cart))
    return jsonify(success=True, count=total_qty)





@app.route('/profile', methods=['POST'])
def update_profile():
    if 'member_id' not in session:
        return redirect('/login')

    name = request.form.get('name')
    phone = request.form.get('phone')
    address = request.form.get('address')
    note = request.form.get('note')

    try:
        member_id = str(UUID(session['member_id']))
        print("👤 會員ID：", member_id)
        print("📦 更新內容：", {"name": name, "phone": phone, "address": address, "note": note})

        result = supabase.table("members").update({
            "name": name,
            "phone": phone,
            "address": address,
            "note": note
        }).filter("id", "eq", member_id).execute()

        print("✅ Supabase 回傳：", result)
        session['profile_updated'] = True

        # ✅ 如果填寫完整，就移除 incomplete_profile
        if name and phone and address:
            session.pop('incomplete_profile', None)

    except Exception as e:
        print("🚨 更新失敗：", e)

    return redirect('/?profile_saved=1')


@app.route('/profile-data')
def profile_data():
    if 'member_id' not in session:
        return jsonify(success=False, message="Not logged in")

    member_id = session['member_id']
    res = supabase.table("members").select("name, phone, address, note").eq("id", member_id).execute()

    if not res.data:
        return jsonify(success=False, message="No data found")

    return jsonify(success=True, data=res.data[0])


# 儲存會員資料
@app.route('/profile.json', methods=['POST'])
def save_profile():
    if 'member_id' not in session:
        return jsonify(success=False, message="Not logged in"), 401

    try:
        member_id = str(UUID(session['member_id']))
    except Exception:
        return jsonify(success=False, message="Invalid member_id in session"), 400

    name    = (request.form.get('name') or '').strip()
    phone   = (request.form.get('phone') or '').strip()
    address = (request.form.get('address') or '').strip()
    note    = (request.form.get('note') or '').strip()

    try:
        res = (supabase.table("members")
               .update({"name": name, "phone": phone, "address": address, "note": note})
               .eq("id", member_id)
               .select("*")
               .execute())
        if not res.data:
            return jsonify(success=False, message="Member not found"), 404

        # 補 profile 完整旗標
        if name and phone and address:
            session.pop('incomplete_profile', None)

        return jsonify(success=True, message="Profile updated successfully")
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500




# 會員歷史訂單路由
@app.route('/order/<int:order_id>')
def order_detail(order_id):
    from pytz import timezone
    from dateutil import parser
    tw = timezone("Asia/Taipei")
    tz = tw

    # 查詢訂單
    res = supabase.table("orders").select("*").eq("id", order_id).single().execute()
    order = res.data
    if not order:
        return "找不到訂單", 404

    # 查詢會員
    member_id = order.get("member_id")
    member = {}
    if member_id:
        res = supabase.table("members").select("username, name, phone, address").eq("id", member_id).single().execute()
        member = res.data or {}

    # 查詢項目
    res = supabase.table("order_items").select("*").eq("order_id", order_id).execute()
    items = res.data or []

    # 時間轉換
    try:
        utc_dt = parser.parse(order['created_at'])
        order['created_local'] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
    except:
        order['created_local'] = order['created_at']

    # === 購物金最低使用門檻（元） ===
    wallet_min_order_amount = int(
        get_setting_num("wallet_min_order_amount_nt", 0)
    )


    return render_template("order_detail.html", order=order, items=items, member=member)

@app.route('/order-history')
def order_history():
    if 'member_id' not in session:
        return redirect('/login?next=order-history')

    member_id = session['member_id']
    tz = TW  # 直接使用全域 TW

    # 查詢會員的所有訂單（新到舊）
    res = (supabase.table("orders")
           .select("*")
           .eq("member_id", member_id)
           .order("created_at", desc=True)
           .execute())
    orders_raw = res.data or []

    # 查詢所有訂單項目（一次撈取）
    res = supabase.table("order_items").select("*").execute()
    items = res.data or []
    item_group = {}
    for item in items:
        item_group.setdefault(item['order_id'], []).append(item)

    # 🔸 新增：把「與訂單關聯」的購物金扣抵撈出來 → {order_id: 使用金額(元)}
    cres = (supabase.table("wallet_credits")
            .select("related_order_id, amount_cents")
            .eq("member_id", member_id)
            .eq("reason", "order_checkout")
            .execute())
    crows = cres.data or []
    wallet_used_map = {}
    for r in crows:
        oid = r.get("related_order_id")
        amt_cents = int(r.get("amount_cents") or 0)  # 負數
        if oid:
            wallet_used_map[oid] = abs(amt_cents) // 100  # 轉元，取絕對值

    # 整合資料 + 台灣時區轉換 + 狀態中文化 + 帶入購物金
    orders = []
    for o in orders_raw:
        o['items'] = item_group.get(o['id'], [])

        # 狀態轉換為中文
        if o.get('status') == 'pending':
            o['status_text'] = '待處理'
        elif o.get('status') == 'paid':
            o['status_text'] = '已付款'
        elif o.get('status') == 'shipped':
            o['status_text'] = '已出貨'
        else:
            o['status_text'] = o.get('status') or '—'

        # 台灣時區
        try:
            utc_dt = parser.parse(o['created_at'])
            o['created_local'] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            o['created_local'] = o.get('created_at', '')

        # 🔸 新增欄位：本筆訂單使用的購物金（元）
        o['wallet_used'] = int(wallet_used_map.get(o['id'], 0))

        orders.append(o)

    return render_template("order_history.html", orders=orders)



# 會員重新下單路由
@app.route('/reorder/<int:order_id>')
def reorder(order_id):
    # 查詢訂單商品
    res = supabase.table("order_items").select("*").eq("order_id", order_id).execute()
    items = res.data or []

    # 初始化購物車
    cart = []
    for item in items:
        product_id = item['product_id']
        qty = item['qty']

        # 查詢商品
        product_res = supabase.table('products').select('*').eq('id', product_id).single().execute()
        if not product_res.data:
            continue
        product = product_res.data

        cart.append({
            'product_id': product_id,
            'name': product['name'],
            'price': product['price'],
            'images': product['images'],
            'qty': qty
        })

    session['cart'] = cart
    return redirect('/cart')

# 首頁最下方關於我、付款方式、配送方式等路由
@app.route('/payment')
def payment():
    return render_template("payment.html")

@app.route('/delivery')
def delivery():
    return render_template("delivery.html")

@app.route('/return')
def return_policy():
    return render_template("return.html")

@app.route('/contact')
def contact():
    return render_template("contact.html")



# 把舊網址導向正確網址
@app.route('/elementor-28/')
def redirect_old_page():
    return redirect("https://herset.co/", code=301)

# 修改密碼
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect('/login')

    account_id = session['user']['account']  # 使用 account 欄位（UUID）

    if request.method == 'POST':
        old_pw = request.form['old_password']
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']

        if new_pw != confirm_pw:
            return render_template('change_password.html', error="新密碼與確認不一致")

        # 查詢該會員目前的密碼
        user_data = supabase.table("members").select("password").eq("account", account_id).execute().data
        if not user_data:
            return render_template('change_password.html', error="找不到會員資料")

        if old_pw != user_data[0]['password']:
            return render_template('change_password.html', error="舊密碼錯誤")

        # 更新密碼
        supabase.table("members").update({"password": new_pw}).eq("account", account_id).execute()

        return render_template('change_password.html', success="密碼已更新成功")

    return render_template('change_password.html')

# 聊聊訊息路由

@app.route('/message')
def message_form():
    if 'member_id' not in session:
        return redirect('/login')
    return render_template('message_form.html')


@app.route('/submit_message', methods=['POST'])
def submit_message():
    if 'member_id' not in session:
        return redirect('/login')

    type = request.form['type']
    subject = request.form['subject']
    content = request.form['content']
    order_number = request.form.get('order_number') or None

        # ===== 取得會員姓名（給 LINE 用）=====
    member_res = (
        supabase.table("members")
        .select("name")
        .eq("id", session['member_id'])
        .single()
        .execute()
    )
    member_name = member_res.data.get("name") if member_res.data else "未知會員"

    file = request.files.get('attachment')
    file_path = None

    if file and file.filename:
        filename = secure_filename(file.filename)
        save_dir = 'static/uploads/messages'
        os.makedirs(save_dir, exist_ok=True)
        filepath = os.path.join(save_dir, f"{uuid4().hex}_{filename}")
        try:
            file.save(filepath)
            file_path = filepath
        except Exception:
            flash("檔案上傳失敗，請確認格式與大小", "danger")
            return redirect('/message')
        
    # ===== 寫入留言 =====
    supabase.table("messages").insert({
        "id": str(uuid4()),
        "member_id": session['member_id'],
        "type": type,
        "subject": subject,
        "content": content,
        "order_number": order_number,
        "attachment_path": file_path,
        "created_at": datetime.utcnow().isoformat()
    }).execute()

  # ===== LINE 留言通知（用姓名，不用 member_id）=====
    try:
        send_line_message_notify({
            "member_name": member_name,   # ✅ 這裡是關鍵
            "type": type,
            "subject": subject,
            "content": content,
            "order_number": order_number or "—"
        })
    except Exception as e:
        app.logger.error(f"[LINE message notify failed] {e}")

    flash("留言送出成功，我們將盡快與您聯繫", "success")
    return render_template("message_success.html")


#管理員主動發送訊息
@app.route("/admin0363/messages/send", methods=["POST"])
def admin_send_message():
    # 1) 權限檢查
    if not session.get("admin_logged_in"):
        flash("尚未登入管理員", "danger")
        return redirect("/admin0363")

    # 2) 取值與基本驗證
    form = request.form
    member_id = (form.get("member_id") or "").strip()
    subject   = (form.get("subject") or "").strip()
    content   = (form.get("content") or "").strip()
    msg_type = (form.get("type") or "其他").strip()
    ALLOWED_TYPES = {"商品問題", "訂單問題", "其他", "系統通知"}
    if msg_type not in ALLOWED_TYPES:
        app.logger.warning(f"[admin_send_message] invalid type '{msg_type}', fallback to '其他'")
        msg_type = "其他"


    if not member_id or not subject or not content:
        flash("請完整填寫：會員、主題、內容", "danger")
        return redirect("/admin0363/dashboard?tab=messages")

    # 3) 產生 payload（沿用你前台徽章規則）
    now_iso = datetime.now(dt_timezone.utc).isoformat()
    payload = {
        # 若你的 messages.id 是 uuid 預設，可改為不傳 id 讓 DB 自生；或保留這行
        "id": str(uuid4()),
        "member_id": member_id,
        "type": msg_type,
        "subject": subject,
        "content": content,
        "order_number": None,
        "attachment_path": None,
        "created_at": now_iso,
        "updated_at": now_iso,
        "is_replied": True,   # 讓會員端顯示「有新回覆」
        "is_read": False,
        "reply_text": None,   # 若想顯示在前台回覆區，也可設為 content
    }

    # 4) 硬派除錯：把收到的表單與 payload 打進 log
    try:
        app.logger.info(f"[admin_send_message] form={dict(form)}")
        app.logger.info(f"[admin_send_message] payload={payload}")
    except Exception:
        pass

    # 5) 嘗試插入 + 立即回讀驗證
    try:
        ins = supabase.table("messages").insert(payload).execute()
        app.logger.info(f"[admin_send_message] insert result={ins.data}")

        # 立即回讀確認（用 id 回查最可靠）
        chk = supabase.table("messages").select("id, member_id, subject") \
            .eq("id", payload["id"]).execute()
        if not chk.data:
            # 若 id 有 DB 預設，或你不傳 id，改以 member_id+subject+時間窗回查
            chk = supabase.table("messages").select("id, member_id, subject") \
                .eq("member_id", member_id) \
                .eq("subject", subject) \
                .gte("created_at", now_iso[:19]) \
                .order("created_at", desc=True) \
                .limit(1).execute()

        if chk.data:
            flash("訊息已送出", "success")
        else:
            # 走到這裡代表 insert 沒丟錯，但回讀不到 → 高機率是 RLS 政策擋住 insert 或欄位型別不合
            flash("已嘗試送出，但未能在資料表中找到紀錄，請檢查 Supabase RLS/欄位設定", "danger")
            app.logger.error("[admin_send_message] Insert seemingly succeeded but record not found. Check RLS/policies/constraints.")
    except Exception as e:
        # 把具體錯誤打 log（例如 RLS、NOT NULL、型別不合）
        app.logger.error(f"[admin_send_message] insert error: {e}", exc_info=True)
        flash(f"發送失敗：{e}", "danger")

    return redirect("/admin0363/dashboard?tab=messages")

# Admin：會員即時搜尋（for autocomplete）
@app.get("/admin0363/members/search")
def admin_member_search():
    if not session.get("admin_logged_in"):
        return jsonify({"error": "unauthorized"}), 401

    q = (request.args.get("q") or "").strip()
    limit = int(request.args.get("limit") or 20)
    if len(q) < 2:
        return jsonify({"items": []})

    # 以 name / email / account 模糊比對
    try:
        # Postgrest 的 OR 語法：欄位.ilike.%關鍵字%
        pattern = f"%{q}%"
        resp = (supabase.table("members")
                .select("id, name, email, account")
                .or_(f"name.ilike.{pattern},email.ilike.{pattern},account.ilike.{pattern}")
                .order("created_at", desc=True)
                .limit(limit)
                .execute())
        items = resp.data or []
        return jsonify({"items": items})
    except Exception as e:
        app.logger.error(f"[admin_member_search] error: {e}")
        return jsonify({"items": []})


#回覆留言（設為已回覆）
@app.route("/admin0363/messages/reply/<msg_id>", methods=["POST"])
def reply_message(msg_id):
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    print("📦 表單內容：", request.form)

    reply_text = request.form.get("reply", "").strip()
    print("🔍 回覆內容：", repr(reply_text))
    print("🔑 留言ID：", msg_id)

    if not reply_text:
        flash("回覆內容不能為空", "danger")
        return redirect("/admin0363/dashboard?tab=messages")

    # 查詢是否有這筆留言
    result_check = supabase.table("messages").select("id").eq("id", msg_id).execute()
    print("🔎 查詢結果：", result_check)

    if not result_check.data:
        flash("找不到這筆留言資料", "danger")
        return redirect("/admin0363/dashboard?tab=messages")

    # 更新留言（強制觸發 updated_at）
    now = datetime.utcnow().isoformat()
    result = supabase.table("messages").update({
        "is_replied": True,
        "is_read": False,
        "reply_text": reply_text,
        "updated_at": now
    }).eq("id", msg_id).execute()
    print("✅ 更新結果：", result)

    # 驗證是否真的寫入成功
    verify = supabase.table("messages").select("reply_text", "is_replied", "updated_at").eq("id", msg_id).execute()
    print("📌 更新後確認：", verify.data)

    flash("已回覆留言", "success")
    return redirect("/admin0363/dashboard?tab=messages")


# 每次頁面刷新時自動檢查是否有新回覆（加上節流＆忽略靜態/健康檢查）
@app.before_request
def check_member_messages():
    # 1) 跳過靜態與健康檢查路徑，避免不必要查詢
    p = request.path or ""
    if (
        p.startswith("/static/") or p == "/favicon.ico" or
        p.startswith("/health") or p.startswith("/ping")
    ):
        return None

    # 2) 未登入 → 清除旗標
    if "member_id" not in session:
        session.pop("has_new_reply", None)
        session.pop("hnr_checked_at", None)
        return None

    member_id = session["member_id"]

    # 3) 節流：60 秒內只檢查一次（避免每頁都打 DB）
    now_ts = int(time.time())
    last_ts = session.get("hnr_checked_at")
    if last_ts and (now_ts - int(last_ts) < 60):
        return None

    # 4) 輕量查詢：只要知道是否存在即可
    try:
        res = (
            supabase.table("messages")
            .select("id", count="exact")
            .eq("member_id", member_id)
            .eq("is_replied", True)
            .eq("is_read", False)
            .limit(1)
            .execute()
        )
        # 有資料（count > 0）代表有新回覆
        has_new = bool(getattr(res, "count", 0))
    except Exception as e:
        app.logger.warning(f"[check_member_messages] query error: {e}")
        has_new = False

    session["has_new_reply"] = has_new
    session["hnr_checked_at"] = now_ts


# 當會員查看訊息時，將已回覆但尚未讀取的留言標記為已讀
@app.route("/member/messages")
def member_messages():
    if "member_id" not in session:
        return redirect("/login")

    tz = TW  # ✅ 全域台灣時區
    member_id = session["member_id"]
    page = max(int(request.args.get("page", 1)), 1)
    per_page = 5
    status = request.args.get("status", "all")  # all | replied | unreplied

    # ---- 跨頁總數（給上方徽章用）以 count 計算，不抓整包 ----
    try:
        all_cnt_res = (
            supabase.table("messages")
            .select("id", count="exact")
            .eq("member_id", member_id)
            .execute()
        )
        count_all = getattr(all_cnt_res, "count", 0) or 0

        replied_cnt_res = (
            supabase.table("messages")
            .select("id", count="exact")
            .eq("member_id", member_id)
            .eq("is_replied", True)
            .execute()
        )
        count_replied = getattr(replied_cnt_res, "count", 0) or 0

        count_unreplied = max(count_all - count_replied, 0)
    except Exception as e:
        app.logger.warning(f"[member_messages] count error: {e}")
        count_all = count_replied = 0
        count_unreplied = 0

    # ---- 依 tab 過濾 + 伺服器端分頁（只取當頁資料）----
    base_q = (
        supabase.table("messages")
        .select("*")
        .eq("member_id", member_id)
        .order("created_at", desc=True)
    )

    if status == "replied":
        base_q = base_q.eq("is_replied", True)
        total = count_replied
    elif status == "unreplied":
        base_q = base_q.eq("is_replied", False)
        total = count_unreplied
    else:
        total = count_all

    # 計算分頁範圍（PostgREST 的 range 是含頭含尾）
    start = (page - 1) * per_page
    end = max(start, start + per_page - 1)

    try:
        page_res = base_q.range(start, end).execute()
        messages = page_res.data or []
    except Exception as e:
        app.logger.warning(f"[member_messages] page query error: {e}")
        messages = []

    has_prev = page > 1
    has_next = (page * per_page) < total

    # ---- 顯示台灣時間 & 是否為新回覆 ----
    for m in messages:
        try:
            m["local_created_at"] = parser.parse(m["created_at"]).astimezone(tz).strftime("%Y-%m-%d %H:%M")
        except Exception:
            m["local_created_at"] = m.get("created_at")
        m["is_new"] = bool(m.get("is_replied") and not m.get("is_read"))

    # ---- 進入頁面即把該會員所有「已回覆未讀」設為已讀（沿用你的策略）----
    try:
        (
            supabase.table("messages")
            .update({"is_read": True})
            .eq("member_id", member_id)
            .eq("is_replied", True)
            .eq("is_read", False)
            .execute()
        )
    except Exception as e:
        app.logger.warning(f"[member_messages] mark read error: {e}")

    # 前端提示徽章也要同步清掉
    session["has_new_reply"] = False

    return render_template(
        "member_messages.html",
        messages=messages,
        page=page,
        has_prev=has_prev,
        has_next=has_next,
        # 👇 徽章數 & 當前狀態
        count_all=count_all,
        count_replied=count_replied,
        count_unreplied=count_unreplied,
        status=status
    )



#全站共用留言has_new_reply
@app.context_processor
def inject_has_new_reply():
    has_reply = False
    if 'member_id' in session:
        res = supabase.table("messages") \
            .select("id") \
            .eq("member_id", session['member_id']) \
            .eq("is_replied", True) \
            .eq("is_read", False) \
            .execute()
        has_reply = len(res.data) > 0

    return dict(has_new_reply=has_reply)



if __name__ == '__main__':
    app.run(debug=True)
