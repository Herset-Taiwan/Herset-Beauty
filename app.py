# --- stdlib
import os, re, json, uuid, random, time, tempfile, urllib.parse, traceback, hmac, base64, hashlib
import requests
from uuid import uuid4, UUID
from uuid import uuid4, UUID
from datetime import datetime, timezone as dt_timezone

# --- third party
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash, send_from_directory, Response, Markup
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client
from postgrest.exceptions import APIError
from flask_mail import Mail, Message
from dateutil import parser
from dotenv import load_dotenv
from pytz import timezone as pytz_timezone
from utils import generate_ecpay_form 


DEFAULT_SHELL_IMAGE = "/static/uploads/logo_0.png"
# （刪掉重複的 import traceback；上面第一行已經有了）
TW = pytz_timezone("Asia/Taipei")


load_dotenv()

# === LINE Pay 設定（先用 Sandbox）===
LINE_PAY_CHANNEL_ID = os.getenv("LINE_PAY_CHANNEL_ID", "你的ChannelId")
LINE_PAY_CHANNEL_SECRET = os.getenv("LINE_PAY_CHANNEL_SECRET", "你的SecretKey")
LINE_PAY_BASE = os.getenv("LINE_PAY_BASE", "https://sandbox-api-pay.line.me")  # 上線改: https://api-pay.line.me

LINE_PAY_REQUEST_URL = f"{LINE_PAY_BASE}/v3/payments/request"
LINE_PAY_CONFIRM_URL = f"{LINE_PAY_BASE}/v3/payments/{{transactionId}}/confirm"

# 站點外部可訪問網址（給 LINE Pay redirect 回來）
SITE_BASE_URL = os.getenv("SITE_BASE_URL") or os.getenv("RENDER_EXTERNAL_URL") or "http://localhost:5000"


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


def generate_merchant_trade_no():
    now = datetime.now().strftime("%Y%m%d%H%M%S")
    rand = random.randint(1000, 9999)
    return f"HS{now}{rand}"

app = Flask(__name__)
app.secret_key = "your_super_secret_key"  # 為了 session 運作，這個很重要
app.secret_key = os.urandom(24)

# ✅ Supabase 初始化
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ✅ 郵件設定
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'hersetbeauty@gmail.com'
app.config['MAIL_PASSWORD'] = 'xlwn swew zqkk fdkt'
app.config['MAIL_DEFAULT_SENDER'] = 'hersetbeauty@gmail.com'
mail = Mail(app)


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

    cart = session.get('cart', [])
    cart_count = sum(item.get('qty', 0) for item in cart)
    return render_template("index.html", products=products, cart_count=cart_count)



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
    return render_template("admin_login.html")

# admin 後台
@app.route("/admin0363/dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    from pytz import timezone
    from dateutil import parser
    import json

    tw = timezone("Asia/Taipei")
    tz = tw
    tab = request.args.get("tab", "products")
    selected_categories = request.args.getlist("category[]")

    # ✅ 商品：搜尋 + 分頁
    product_keyword = request.args.get("product_keyword", "").lower()
    product_page = int(request.args.get("page", 1))
    product_page_size = int(request.args.get("page_size", 10))
    product_start = (product_page - 1) * product_page_size
    product_end = product_start + product_page_size

    product_query = supabase.table("products").select("*")
    if selected_categories:
        filters = [f"categories.cs.{json.dumps([cat])}" for cat in selected_categories]
        product_query = product_query.or_(','.join(filters))

    all_products = product_query.execute().data or []
    if product_keyword:
        all_products = [
            p for p in all_products
            if product_keyword in p.get("name", "").lower()
        ]
    # 🔥 新增：計算「目前篩選後」的分類數量與合計
    category_counts = {}
    for p in all_products:
        cats = p.get("categories") or []
        for c in cats:
            category_counts[c] = category_counts.get(c, 0) + 1

    if selected_categories:
        # 逐一列出使用者有選的分類數量
        selected_category_counts = {c: category_counts.get(c, 0) for c in selected_categories}
        # 合計 = 目前篩選後的商品數（不會重複計）
        product_total_count = len(all_products)
    else:
        selected_category_counts = {}
        product_total_count = len(all_products)
    product_total_pages = max(1, (product_total_count + product_page_size - 1) // product_page_size)
    products = all_products[product_start:product_end]

            # 取得所有 bundles，建立 (shell_product_id -> bundle_id) 對照
    bundle_map_rows = supabase.table("bundles").select("id, shell_product_id").execute().data or []
    shell_to_bundle = {b["shell_product_id"]: b["id"] for b in bundle_map_rows if b.get("shell_product_id")}

    # 把對照寫回 products（讓模板能拿到 p['bundle_id']）
    for p in products:
        if p.get("product_type") == "bundle":
            p["bundle_id"] = shell_to_bundle.get(p.get("id"))





    # ✅ 會員
    members = supabase.table("members").select(
        "id, account, username, name, phone, email, address, note, created_at"
    ).execute().data or []
    member_total_count = len(members)   # 新增：會員總數
    for m in members:
        try:
            if m.get("created_at"):
                utc_dt = parser.parse(m["created_at"])
                m["created_at"] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except:
            m["created_at"] = m.get("created_at", "—")
    member_dict = {m["id"]: m for m in members}
    # 未回覆留言數（is_replied = False）


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
        # 🔥 會員分頁（預設每頁 5 筆）
    member_page = int(request.args.get("member_page", 1))
    member_page_size = int(request.args.get("member_page_size", 5))

    member_total_count_filtered = len(members)  # 目前篩選後的總筆數
    member_total_pages = max(1, (member_total_count_filtered + member_page_size - 1) // member_page_size)

    member_start = (member_page - 1) * member_page_size
    member_end = member_start + member_page_size
    members = members[member_start:member_end]


    # ✅ 訂單
    order_page = int(request.args.get("order_page", 1))
    order_page_size = int(request.args.get("order_page_size", 20))
    order_start = (order_page - 1) * order_page_size
    order_end = order_start + order_page_size - 1

    order_total_res = supabase.table("orders").select("id", count="exact").execute()
    order_total_count = order_total_res.count or 0

    orders_raw = supabase.table("orders") \
        .select("*") \
        .order("created_at", desc=True) \
        .range(order_start, order_end) \
        .execute().data or []

    order_ids = [o["id"] for o in orders_raw]
    member_ids = list({o["member_id"] for o in orders_raw if o.get("member_id")})

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
            "address": member.get("address") if member else "—"
        }
        o["is_new"] = bool(o.get("status") != "shipped" and not session.get("seen_orders"))
        try:
            utc_dt = parser.parse(o["created_at"])
            o["created_local"] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except:
            o["created_local"] = o["created_at"]
        orders.append(o)
        # 未出貨訂單數
    unshipped_count = sum(1 for o in orders if (o.get("status") != "shipped"))

    # ✅ 留言 + 分頁
    reply_status = request.args.get("reply_status", "all")
    msg_type = request.args.get("type", "")
    msg_keyword = request.args.get("keyword", "").lower()
    msg_page = int(request.args.get("msg_page", 1))
    msg_page_size = int(request.args.get("msg_page_size", 10))

    all_messages = supabase.table("messages") \
        .select("*") \
        .order("created_at", desc=True) \
        .execute().data or []

    member_ids = list({m['member_id'] for m in all_messages})
    name_map = {}
    if member_ids:
        members_res = supabase.table("members").select("id, name").in_("id", member_ids).execute().data or []
        name_map = {m['id']: m['name'] for m in members_res}

    for m in all_messages:
        m["member_name"] = name_map.get(m.get("member_id"), "未知")
        m["is_new"] = bool(not m.get("is_replied") and not session.get("seen_messages"))
        try:
            utc_dt = parser.parse(m["created_at"])
            m["local_created_at"] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M")
        except:
            m["local_created_at"] = m["created_at"]
            #  未回覆留言數（依全部留言計算）
    unreplied_count = sum(1 for m in all_messages if not m.get("is_replied"))

    filtered_messages = []
    for m in all_messages:
        match_status = (
            reply_status == "all" or
            (reply_status == "replied" and m.get("is_replied")) or
            (reply_status == "unreplied" and not m.get("is_replied"))
        )
        match_type = not msg_type or m.get("type") == msg_type
        match_name = not msg_keyword or msg_keyword in (m.get("member_name") or "").lower()

        if match_status and match_type and match_name:
            filtered_messages.append(m)

    msg_total_count = len(filtered_messages)
    msg_total_pages = max(1, (msg_total_count + msg_page_size - 1) // msg_page_size)
    msg_start = (msg_page - 1) * msg_page_size
    msg_end = msg_start + msg_page_size
    paged_messages = filtered_messages[msg_start:msg_end]

    # ✅ 提示狀態
    new_order_alert = any(o.get("status") != "shipped" for o in orders)
    new_message_alert = any(not m.get("is_replied") for m in all_messages)
    show_order_alert = new_order_alert and not session.get("seen_orders")
    show_message_alert = new_message_alert and not session.get("seen_messages")

    # ✅ 回傳前再標記為已讀
    question_types = ["商品問題", "訂單問題", "其他"]
    response = render_template("admin.html",
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
        # 🔥 新增傳入模板的變數（動態顯示用）
    product_total_count=product_total_count,
    selected_category_counts=selected_category_counts,
    category_counts=category_counts,
    unshipped_count=unshipped_count,
    unreplied_count=unreplied_count,
     # 會員分頁用
    member_page=member_page,
    member_total_pages=member_total_pages,
    member_page_size=member_page_size,
    )

    session["seen_orders"] = True
    session["seen_messages"] = True
    return response

# ================================
#  後台：新增套組（顯示頁）
#  URL: GET /admin0363/bundles/new
# ================================
@app.route("/admin0363/bundles/new", methods=["GET", "POST"])
def admin_new_bundle():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    if request.method == "POST":
        try:
            # --- 1) 讀取表單欄位 ---
            name = (request.form.get("name") or "").strip()
            price = float(request.form.get("price") or 0)        # 套組現價（顯示用）
            compare_at = request.form.get("compare_at")          # 套組原價（劃線價）
            compare_at = float(compare_at) if compare_at else None
            stock = int(request.form.get("stock") or 0)

            required_total = int(request.form.get("required_total") or 0)  # 逐步挑選件數
            categories = request.form.getlist("categories[]")
            tags = request.form.getlist("tags[]")  # new_bundle.html 的 name="tags[]"
            intro = (request.form.get("intro") or "").strip()
            feature = (request.form.get("feature") or "").strip()
            spec = (request.form.get("spec") or "").strip()
            description = (request.form.get("description") or "").strip()  # 後台備註（bundles 專用）

            # 可選商品池（僅單品 id）
            pool_ids = request.form.getlist("pool_ids[]")
            pool_ids = [int(x) for x in pool_ids if str(x).strip().isdigit()]

            # --- 2) 封面圖（上傳到 images bucket/product_images/） ---
            cover_url = None
            cover_file = request.files.get("cover_image")
            if cover_file and cover_file.filename:
                filename = secure_filename(cover_file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                storage_path = f"product_images/{unique_filename}"
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    cover_file.save(tmp.name)
                    supabase.storage.from_("images").upload(storage_path, tmp.name)
                    cover_url = supabase.storage.from_("images").get_public_url(storage_path)

            # --- 3) 影片處理（上傳檔 + 連結） ---
            # 3-1 表單貼連結
            video_urls_from_form = [
                (u or "").strip()
                for u in request.form.getlist("video_urls[]")
                if (u or "").strip()
            ]

            # 3-2 上傳檔（放到 images bucket/bundle_videos/）
            allowed_video_ext = {"mp4", "webm", "ogv", "mov", "m4v"}
            video_urls_from_upload = []
            for vf in request.files.getlist("video_files"):
                if not vf or not vf.filename:
                    continue
                ext = (vf.filename.rsplit(".", 1)[-1] or "").lower()
                if ext not in allowed_video_ext:
                    print(f"⚠️ 略過不支援的影片格式：{vf.filename}")
                    continue
                v_name = secure_filename(vf.filename)
                v_unique = f"{uuid.uuid4()}_{v_name}"
                v_path = f"bundle_videos/{v_unique}"
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    vf.save(tmp.name)
                    supabase.storage.from_("images").upload(v_path, tmp.name)
                    v_url = supabase.storage.from_("images").get_public_url(v_path)
                    video_urls_from_upload.append(v_url)

            videos = video_urls_from_upload + video_urls_from_form  # 合併

            # --- 4) 先建立 products（殼商品，product_type='bundle'） ---
            product_data = {
                "name": name,
                "price": price,              # 前台顯示現價
                "stock": stock,
                "image": cover_url,          # 封面圖
                "images": [],                # 套組目前沒有多圖上傳欄位，先給空陣列
                "intro": intro,
                "feature": feature,
                "spec": spec,
                "ingredient": "",            # 套組不使用，可留空
                "options": [],               # 套組不使用此欄（由 bundles 控制）
                "categories": categories,
                "tags": tags,
                "product_type": "bundle",
                "videos": videos,            # ✅ 套組也能在商品頁相簿顯示影片
            }
            pres = supabase.table("products").insert(product_data).execute()
            if hasattr(pres, "error") and pres.error:
                return f"建立套組殼商品失敗：{pres.error['message']}", 500
            new_product = (pres.data or [None])[0]
            if not new_product:
                return "建立套組殼商品失敗：未知錯誤", 500
            product_id = new_product["id"]

            # --- 5) 再建立 bundles 明細（與殼商品關聯） ---
            # 若你的專案已建立 bundles 表，欄位建議：product_id, compare_at, required_total, pool_ids(jsonb), description(text)
            bundle_row = {
                "product_id": product_id,
                "compare_at": compare_at,          # 原價（劃線價）
                "required_total": required_total,  # 逐步挑選件數
                "pool_ids": pool_ids,              # 可選商品池（jsonb）
                "description": description,        # 後台備註
            }
            bres = supabase.table("bundles").insert(bundle_row).execute()
            if hasattr(bres, "error") and bres.error:
                return f"建立套組明細失敗：{bres.error['message']}", 500

            # --- 6) 完成 ---
            return redirect("/admin0363/dashboard?tab=products")

        except Exception as e:
            print("🔥 新增套組錯誤：", e)
            traceback.print_exc()
            return f"新增套組時發生錯誤：{str(e)}", 500

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

    # ✅ 新增哪一段：影片處理（保留舊 + 新增連結 + 新上傳）
    kept_videos = request.form.getlist("existing_videos[]")  # 由編輯頁現有清單（hidden）帶回
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

    # 1) 更新 bundles 主檔（🔸這裡「取代」你原本 update 的 dict，加入 videos）
    update_data = {
        "name": name,
        "price": price,
        "compare_at": compare_at,
        "stock": stock,
        "description": description,
        "required_total": required_total,
        "categories": final_categories,
        "tags": final_tags,
        "videos": videos,  # ✅
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

    # 4) 同步殼商品（intro/feature/spec/封面 & 影片）
    bres = (
        supabase.table("bundles")
        .select("shell_product_id, cover_image")
        .eq("id", bundle_id).limit(1).execute()
    )
    bundle_row = (bres.data or [None])[0] or {}
    shell_id = bundle_row.get("shell_product_id")
    current_cover = cover_image_url or bundle_row.get("cover_image") or DEFAULT_SHELL_IMAGE

    if not shell_id:
        # 沒殼就補建
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
                    "videos": videos,  # ✅ 一併帶入
                })
                .execute()
            )
            shell_id = shell_insert.data[0]["id"]
            supabase.table("bundles").update({"shell_product_id": shell_id}).eq("id", bundle_id).execute()
        except Exception as e:
            print("❗️建立套組殼品項失敗：", e)
    else:
        # 更新既有殼商品
        shell_update = {
            "name": f"[套組優惠] {name}",
            "price": price,
            "stock": stock,
            "intro": intro,
            "feature": feature,
            "spec": spec,
            "categories": final_categories,
            "tags": final_tags,
            "videos": videos,  # ✅ 同步影片
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

        res = supabase.table("members") \
            .select("id, account, password, name, phone, address") \
            .eq("account", account).execute()

        if res.data and res.data[0]['password'] == password:
            user = res.data[0]
            session['user'] = user
            session['member_id'] = user['id']

            # ✅ 判斷是否有缺資料
            if not user.get('name') or not user.get('phone') or not user.get('address'):
                session['incomplete_profile'] = True
            else:
                session.pop('incomplete_profile', None)

            return redirect('/cart' if next_page == 'cart' else '/')

        else:
            return render_template("login.html", error="帳號或密碼錯誤")

    return render_template("login.html")


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
        return render_template("register.html", error="此帳號已被使用")

    try:
        # 建議寫入 UTC（避免 tz 未定義、排序也穩定）
        created_at = datetime.utcnow().isoformat() + "Z"

        # 不給 id 由 Supabase 產生
        resp = supabase.table("members").insert({
            "account": account,
            "email": email,
            "password": password,   # 你目前存明碼；若要改成雜湊再說
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

        # 首次登入引導補資料
        session['incomplete_profile'] = True

        return render_template("register_success.html")

    except Exception as e:
        app.logger.error(f"🚨 註冊錯誤：{e}")
        return render_template("register.html", error="註冊失敗，請稍後再試")




@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/about')
def about():
    return render_template('about.html')


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

        # 🔹 新增：把套組選擇的內容整理成可顯示的行列
        bundle_lines = []
        if (item.get('product_type') or dbp.get('product_type')) == 'bundle':
            # 可能的欄位 1：list[dict]，例如 [{'name':'A', 'qty':2}, ...]
            if isinstance(item.get('bundle_items'), list) and item['bundle_items']:
                for c in item['bundle_items']:
                    nm = c.get('name') or c.get('title') or c.get('product_name') or c.get('label')
                    q = int(c.get('qty') or c.get('count') or 1)
                    if nm:
                        nm = _clean_bundle_label(nm)
                        bundle_lines.append(f"{nm} × {q}" if q > 1 else nm)

            # 可能的欄位 2：list[...]，例如 ['A','B'] 或 [{'label':'A'}]
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
            # 可能的欄位 3：文字（用逗號/換行/頓號分隔）
            elif item.get('option'):
                text = str(item['option']).strip()
                parts = [_clean_bundle_label(p) for p in re.split(r'[,\n、|｜]+', text) if p.strip()]
                bundle_lines.extend(parts)

        product_out = {
            'id': pid,
            'name': dbp.get('name') or item.get('name'),
            'product_type': item.get('product_type') or dbp.get('product_type'),

            # ✅ 仍保留套組價格欄位
            'bundle_price':   item.get('bundle_price'),
            'bundle_compare': item.get('bundle_compare'),

            # 前端顯示/計算會用到的欄位
            'price': unit_price,
            'original_price': unit_compare if unit_compare > 0 else unit_price,
            'discount_price': unit_discount if (unit_discount and unit_compare and unit_discount < unit_compare) else 0.0,
            'qty': qty,
            'subtotal': unit_price * qty,

            # 🔹 新增：給模板顯示的套組行
            'bundle_lines': bundle_lines,

            'option': item.get('option', ''),
            'image': image,
            'images': images,
        }


        products.append(product_out)
        total += product_out['subtotal']

    # 運費計算（維持你原規則）
    shipping_fee = 0 if total >= 2000 else 80
    free_shipping_diff = 0 if total >= 2000 else (2000 - total)

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

    return render_template(
        "cart.html",
        products=products,
        total=total,
        shipping_fee=shipping_fee,
        final_total=final_total,
        free_shipping_diff=free_shipping_diff,
        discount=discount,
        discount_deduct=discount_deduct,
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

    # 1) 組商品明細 + 算小計（以加入購物車時記錄的價格為主）
    total = 0.0
    items = []
    for item in cart_items:
        pid = item.get('product_id')
        if not pid:
            continue
        # 撈必要欄位（名稱），價格仍以購物車為準
        res = supabase.table("products").select("id,name").eq("id", pid).single().execute()
        product = res.data or {}

        # 單價：購物車記錄的 price 優先；若沒有再回退 DB price/discount_price
        item_price = float(item.get('price')
                           or item.get('discount_price')
                           or product.get('discount_price')
                           or product.get('price')
                           or 0)
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

    # 2) 運費（依小計判斷免運；不受折扣影響）
    shipping_fee = 0 if total >= 2000 else 80

    # 3) 折扣碼（再次驗證後套用，不讓無效碼寫入訂單）
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
            session.pop('cart_discount', None)  # 無效就清掉

    # 4) 應付金額（不得為負）
    final_total = max(total + shipping_fee - discount_amount, 0)

    # 5) 建立訂單
    from uuid import uuid4
    from pytz import timezone
    from datetime import datetime
    tw = timezone("Asia/Taipei")
    tz = tw
    merchant_trade_no = "HS" + uuid4().hex[:12]
    created_at = datetime.now(tw).isoformat()


    order_data = {
        'member_id': member_id,
        'total_amount': final_total,      # 實際應付金額（含運、扣完折扣）
        'shipping_fee': shipping_fee,
        'discount_code': discount_code,   # 需要先加欄位（見下方 SQL）
        'discount_amount': discount_amount,
        'status': 'pending',
        'created_at': created_at,
        'MerchantTradeNo': merchant_trade_no
    }
    result = supabase.table('orders').insert(order_data).execute()
    order_id = result.data[0]['id']

    # 6) 寫入每筆商品明細
    for it in items:
        it['id'] = str(uuid4())
        it['order_id'] = order_id
        it['option'] = it.get('option', '')
    supabase.table('order_items').insert(items).execute()

    # 7) 成功後才累計折扣使用次數（簡單版；想更嚴謹可用 RPC，見下）
    if discount_code:
        try:
            d = supabase.table('discounts').select('used_count').eq('code', discount_code).single().execute().data or {}
            used = int(d.get('used_count') or 0) + 1
            supabase.table('discounts').update({'used_count': used}).eq('code', discount_code).execute()
        except Exception:
            # 若失敗就略過，不影響下單
            pass

    # 8) 清空購物車與折扣碼暫存、保存交易編號
    session['cart'] = []
    session.pop('cart_discount', None)
    session['current_trade_no'] = merchant_trade_no

    return redirect("/choose-payment")




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


#執行付款動作
@app.route('/pay', methods=['POST'])
def pay():
    method = request.form.get("method")
    trade_no = session.get("current_trade_no")

    res = supabase.table("orders").select("*").eq("MerchantTradeNo", trade_no).execute()
    if not res.data:
        return "找不到訂單", 404

    order = res.data[0]

    if method == "credit":
        from utils import generate_ecpay_form
        return generate_ecpay_form(order, trade_no)
    elif method == "bank":
        return render_template("bank_transfer.html", order=order)
    elif method == "linepay":
        return "Line Pay 尚未整合"
    else:
        return "付款方式錯誤", 400
    


 #line pay結帳完成回傳
@app.route("/linepay/notify", methods=["POST"])
def linepay_notify():
    try:
        data = request.get_json()

        # 假設 orderId 是訂單號（你可以根據真實格式調整）
        order_id = int(data.get("orderId"))
        status = data.get("transactionStatus")

        if status == "SUCCESS":
            supabase.table("orders").update({
                "payment_status": "paid"
            }).eq("id", order_id).execute()
            print(f"✅ 已更新訂單 {order_id} 為已付款")

        return "OK", 200

    except Exception as e:
        print("❌ LinePay Webhook 錯誤:", e)
        return "FAIL", 500

def _lp_signature_headers(api_path: str, body_obj: dict | None, method: str = "POST"):
    """
    依 v3 規格計算 X-LINE-Authorization 與 X-LINE-Authorization-Nonce
    POST: signature over (channelSecret + apiPath + jsonBody + nonce)
    GET : signature over (channelSecret + apiPath + queryString + nonce)  # 若有需要才用
    """
    nonce = str(uuid4())

    payload_str = ""
    if method.upper() == "POST":
        # 重要：JSON 要無空白，鍵值順序照 dumps 輸出即可
        payload_str = json.dumps(body_obj or {}, separators=(",", ":"))
        message = LINE_PAY_CHANNEL_SECRET + api_path + payload_str + nonce
    else:
        # GET 若有 queryString，請自行串在這裡
        message = LINE_PAY_CHANNEL_SECRET + api_path + "" + nonce

    mac = hmac.new(
        LINE_PAY_CHANNEL_SECRET.encode("utf-8"),
        msg=message.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    signature = base64.b64encode(mac).decode("utf-8")

    return {
        "Content-Type": "application/json",
        "X-LINE-ChannelId": LINE_PAY_CHANNEL_ID,
        "X-LINE-Authorization-Nonce": nonce,
        "X-LINE-Authorization": signature,
    }


def _order_amount_currency(order):
    """
    從訂單取得實際應付金額與幣別（checkout 已寫入 orders.total_amount）
    """
    amount = int(round(float(order.get("total_amount", 0))))  # ← 正確欄位
    if amount <= 0:
        raise ValueError("LINE Pay 金額為 0，請檢查 orders.total_amount 寫入流程")
    currency = order.get("currency", "TWD")
    return amount, currency




# 判斷用戶選的付款方式
@app.route("/process_payment", methods=["POST"])
def process_payment():
    order_id = request.form.get("order_id")
    method = request.form.get("method")
    is_repay = request.form.get("is_repay") == "1"

    # 查詢訂單
    order = supabase.table("orders").select("*").eq("id", order_id).single().execute().data
    if not order:
        return "找不到訂單", 404

    if method == "linepay":
        # 👉 正確縮排，且整個 linepay 分支結束後才接續 elif bank/credit
        amount, currency = _order_amount_currency(order)

        body = {
            "amount": amount,
            "currency": currency,
            "orderId": f"LP-{order['id']}",
            "packages": [{
                "id": "pkg-1",
                "amount": amount,
                "name": "HERSET 訂單",
                "products": [{
                    "name": f"訂單 {order['id']} 總額",
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
        headers = _lp_signature_headers(api_path, body, method="POST")

        # 確保簽名用的字串與送出的字串一致
        payload = json.dumps(body, separators=(",", ":"))

        r = requests.post(f"{LINE_PAY_BASE}{api_path}", headers=headers, data=payload)
        data = r.json()

        if data.get("returnCode") == "0000":
            payment_url = data["info"]["paymentUrl"]["web"]
            # 記為待付款
            supabase.table("orders").update({
    "payment_status": "pending"
}).eq("id", order["id"]).execute()
            return redirect(payment_url)
        else:
            return f"LINE Pay 建立失敗：{data}", 400

    elif method == "bank":
        return render_template("bank_transfer.html", order=order)  # 顯示轉帳資料

    elif method == "credit":
        # 產生新的 MerchantTradeNo，避免與原本的衝突
        new_trade_no = "HS" + uuid4().hex[:12]
        supabase.table("ecpay_repay_map").insert({
            "original_trade_no": order["MerchantTradeNo"],
            "new_trade_no": new_trade_no,
            "order_id": order["id"]
        }).execute()

        # 產生 ECPay 表單 HTML
        html = generate_ecpay_form(order, trade_no=new_trade_no)

        # 回傳 HTML，瀏覽器會自動跳轉至綠界頁面
        return Response(html, content_type='text/html; charset=utf-8')

    else:
        return "未知付款方式", 400

# Linepay 付款成功後 confirm（v3 簽名版）
@app.route("/linepay/confirm")
def linepay_confirm():
    transaction_id = request.args.get("transactionId", "")
    order_id = request.args.get("order_id", "")
    if not transaction_id or not order_id:
        return "參數不足：缺少 transactionId 或 order_id", 400

    # 查訂單
    res = supabase.table("orders").select("*").eq("id", order_id).single().execute()
    order = res.data
    if not order:
        return "找不到訂單", 404

    amount, currency = _order_amount_currency(order)

    # === v3 確認付款：簽名 + POST ===
    confirm_body = {"amount": amount, "currency": currency}
    confirm_path = f"/v3/payments/{transaction_id}/confirm"

    # 用與簽名相同的 JSON 字串（無多餘空白）
    payload = json.dumps(confirm_body, separators=(",", ":"))

    # 產 header（需先有 _lp_signature_headers，見下方「新增哪一段」）
    headers = _lp_signature_headers(confirm_path, confirm_body, method="POST")

    r = requests.post(f"{LINE_PAY_BASE}{confirm_path}",
                      headers=headers,
                      data=payload)
    data = r.json()

    if data.get("returnCode") == "0000":
        supabase.table("orders").update({
    "payment_status": "paid",
    "paid_trade_no": transaction_id
}).eq("id", order_id).execute()
        return redirect("/thank-you")

    else:
        # 你也可以把 data 記 log 方便除錯
        return redirect("/cart")

        
#Linepay取消返回
@app.route("/payment_cancel")
def linepay_cancel():
    order_id = request.args.get("order_id", "")
    return redirect(f"/order/cancel/{order_id}" if order_id else "/")

# 歷史訂單重新付款
@app.route("/repay/<merchant_trade_no>")
def repay_order(merchant_trade_no):
    # 查原始訂單
    order_result = supabase.table("orders").select("*").eq("MerchantTradeNo", merchant_trade_no).execute()
    if not order_result.data:
        return "找不到對應的訂單", 404

    order = order_result.data[0]

    # 顯示付款方式選擇畫面
    return render_template("choose_payment.html", order=order, is_repay=True)







@app.route('/thank_you')
@app.route('/thank-you')
def thank_you():
    return render_template("thank_you.html")


#後台訂單狀態修改
@app.route('/admin0363/orders/update_status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    new_status = request.form.get("status")
    if new_status:
        supabase.table("orders").update({"status": new_status}).eq("id", order_id).execute()
        flash(f"訂單 #{order_id} 出貨狀態已修改")  # ← ✅ 修改訊息內容
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
        required_total=required_total
    )




#綠界付款成功回傳處理
@app.route('/ecpay/return', methods=['POST'])
def ecpay_return():
    data = request.form.to_dict()
    if data.get('RtnCode') == '1':
        supabase.table("orders").update({'status': 'paid'}).eq('MerchantTradeNo', data['MerchantTradeNo']).execute()
        return '1|OK'
    return '0|Fail'
#綠界付款成功回傳處理

#重新付款處理
@app.route("/ecpay/return", methods=["POST"])
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
            "payment_time": payment_date,
            "paid_trade_no": merchant_trade_no
        }).eq("id", order["id"]).execute()

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



#刪除訂單
@app.route('/admin0363/orders/delete/<int:order_id>', methods=['POST'])
def delete_order(order_id):
    supabase.table("orders").delete().eq("id", order_id).execute()
    supabase.table("order_items").delete().eq("order_id", order_id).execute()
    return redirect('/admin0363/dashboard')



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
            "tags": tags
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


# 加入購物車
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_id = request.form.get('product_id')
    qty       = int(request.form.get('qty', 1))
    option    = (request.form.get('option') or '')
    action    = request.form.get('action')

    # 1) 取商品
    res = supabase.table('products').select('*').eq('id', product_id).single().execute()
    if not res.data:
        return jsonify(success=False, message="找不到商品"), 404
    product = res.data

    is_bundle = (product.get('product_type') == 'bundle')

    # 2) 基本價（單品）
    orig = float(product.get('price') or 0)                # 原價
    disc = float(product.get('discount_price') or 0)       # 單品折扣價（沒有就 0）
    cur  = disc if (disc and disc < orig) else orig        # 結帳用單價（先用單品邏輯）

    # 3) 套組價（覆蓋）
    bundle_price = None
    bundle_compare = None
    if is_bundle:
        try:
            b = (
                supabase.table('bundles')
                .select('price, compare_at, shell_product_id')
                .eq('shell_product_id', product_id)   # ✅ 正確欄位
                .single()
                .execute()
                .data
            )
            if b:
                bp = float(b.get('price') or 0)
                bc = float(b.get('compare_at') or 0)
                if bp > 0:
                    cur = bp               # 套組現價 → 計價用
                    bundle_price = bp
                if bc > 0:
                    orig = bc              # 套組原價 → 顯示用
                    bundle_compare = bc
        except Exception:
            pass

    # 4) 初始化購物車
    session.setdefault('cart', [])
    cart = session['cart']

    # 5) 若已有相同商品+規格，直接加量
    for item in cart:
        if item.get('product_id') == product_id and (item.get('option') or '') == option:
            item['qty'] += qty
            session.modified = True
            if action == 'checkout':
                return redirect('/cart')
            total_qty = sum(x.get('qty', 0) for x in cart)
            return jsonify(success=True, count=total_qty)

    # 6) 新增項目
    entry = {
        'id': product_id,
        'product_id': product_id,
        'name': product.get('name'),
        'price': cur,                          # 小計用
        'original_price': orig,                # 給頁面顯示
        'discount_price': (disc if (disc and disc < orig) else 0),  # 單品才會有意義
        'images': product.get('images', []),
        'qty': qty,
        'option': option
    }
    if bundle_price is not None:
        entry['bundle_price'] = bundle_price
    if bundle_compare is not None:
        entry['bundle_compare'] = bundle_compare

    cart.append(entry)
    session['cart'] = cart
    session.modified = True

    # 7) 立即結帳
    if action == 'checkout':
        return redirect('/cart')

    # 8) 一般加入購物車回傳數量
    total_qty = sum(x.get('qty', 0) for x in cart)
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

    return render_template("order_detail.html", order=order, items=items, member=member)

@app.route('/order-history')
def order_history():
    if 'member_id' not in session:
        return redirect('/login?next=order-history')

    member_id = session['member_id']
    tz = TW  # 直接使用全域 TW

    # 查詢會員的所有訂單
    res = supabase.table("orders") \
        .select("*") \
        .eq("member_id", member_id) \
        .order("created_at", desc=True).execute()
    orders_raw = res.data or []

    # 查詢所有訂單項目（一次撈取）
    res = supabase.table("order_items").select("*").execute()
    items = res.data or []
    item_group = {}
    for item in items:
        item_group.setdefault(item['order_id'], []).append(item)

    # 整合資料 + 台灣時區轉換 + 狀態中文化
    orders = []
    for o in orders_raw:
        o['items'] = item_group.get(o['id'], [])

        # 狀態轉換為中文
        if o['status'] == 'pending':
            o['status_text'] = '待處理'
        elif o['status'] == 'paid':
            o['status_text'] = '已付款'
        elif o['status'] == 'shipped':
            o['status_text'] = '已出貨'
        else:
            o['status_text'] = o['status']  # fallback 顯示原文

        try:
            utc_dt = parser.parse(o['created_at'])
            o['created_local'] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except:
            o['created_local'] = o['created_at']

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

    flash("留言送出成功，我們將盡快與您聯繫", "success")
    return render_template("message_success.html")


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





#每次頁面刷新時都會自動檢查是否有新回覆
@app.before_request
def check_member_messages():
    if "member_id" in session:
        member_id = session["member_id"]
        res = supabase.table("messages") \
            .select("id") \
            .eq("member_id", member_id) \
            .eq("is_replied", True) \
            .eq("is_read", False) \
            .execute()
        session["has_new_reply"] = bool(res.data)
    else:
        session.pop("has_new_reply", None)

# 當會員查看訊息時，將已回覆但尚未讀取的留言標記為已讀
@app.route("/member/messages")
def member_messages():
    if "member_id" not in session:
        return redirect("/login")

    tz = TW  # ✅ 全域台灣時區
    member_id = session["member_id"]
    page = int(request.args.get("page", 1))
    per_page = 5
    status = request.args.get("status", "all")  # all | replied | unreplied

    # 取出該會員全部留言（新→舊）
    all_messages = (supabase.table("messages")
        .select("*")
        .eq("member_id", member_id)
        .order("created_at", desc=True)
        .execute().data or [])

    # ✅ 跨頁總數（給上方徽章用）
    count_all = len(all_messages)
    count_replied = sum(1 for m in all_messages if m.get("is_replied"))
    count_unreplied = count_all - count_replied

    # 顯示台灣時間 & 是否為新回覆
    for m in all_messages:
        try:
            m["local_created_at"] = parser.parse(m["created_at"]).astimezone(tz).strftime("%Y-%m-%d %H:%M")
        except Exception:
            m["local_created_at"] = m["created_at"]
        m["is_new"] = bool(m.get("is_replied") and not m.get("is_read"))

    # ✅ 依 tab 過濾（不影響上方三個總數）
    if status == "replied":
        working = [m for m in all_messages if m.get("is_replied")]
    elif status == "unreplied":
        working = [m for m in all_messages if not m.get("is_replied")]
    else:
        working = all_messages

    # 分頁（針對過濾後的集合）
    total = len(working)
    start = (page - 1) * per_page
    end = start + per_page
    messages = working[start:end]
    has_prev = page > 1
    has_next = end < total

    # 設為已讀（沿用你的做法：進入頁面即把該會員所有「已回覆未讀」設為已讀）
    if messages:
        (supabase.table("messages")
            .update({"is_read": True})
            .eq("member_id", member_id)
            .eq("is_replied", True)
            .eq("is_read", False)
            .execute())

    session["has_new_reply"] = False

    return render_template("member_messages.html",
                           messages=messages,
                           page=page,
                           has_prev=has_prev,
                           has_next=has_next,
                           # 👇 新增給模板的徽章數 & 當前狀態
                           count_all=count_all,
                           count_replied=count_replied,
                           count_unreplied=count_unreplied,
                           status=status)



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
