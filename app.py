
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash, send_from_directory, Response, Markup
from werkzeug.utils import secure_filename
from supabase import create_client, Client
from flask_mail import Mail, Message
from datetime import datetime
from dateutil import parser
from pytz import timezone
from dotenv import load_dotenv
from uuid import uuid4
from datetime import datetime
from pytz import timezone
from werkzeug.security import generate_password_hash
from postgrest.exceptions import APIError
import os
import tempfile
import urllib.parse
import hashlib
import random
import time
import uuid
import json
import uuid, tempfile
from uuid import UUID
from flask import redirect

from utils import generate_check_mac_value, generate_ecpay_form


load_dotenv()


    
def generate_check_mac_value(params, hash_key, hash_iv):
    # 1. 將參數依照字母順序排列
    sorted_params = sorted(params.items())

    # 2. 組合字串
    raw = f'HashKey={hash_key}&' + '&'.join([f'{k}={v}' for k, v in sorted_params]) + f'&HashIV={hash_iv}'

    # 3. URL Encode（小寫）並取代特殊字元
    encoded = urllib.parse.quote_plus(raw).lower()

    # 4. SHA256 加密，轉成大寫十六進位
    check_mac = hashlib.sha256(encoded.encode('utf-8')).hexdigest().upper()
    return check_mac

def generate_merchant_trade_no():
    now = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
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

    tz = timezone("Asia/Taipei")
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
@app.route("/admin0363/bundles/new", methods=["GET"])
def admin_new_bundle():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    # 只抓單品當可選池
    products = (
        supabase.table("products")
        .select("id,name,price,product_type")
        .eq("product_type", "single")
        .order("name")
        .execute()
        .data
        or []
    )
    return render_template("new_bundle.html", products=products)


# ================================
#  後台：新增套組（儲存）
#  URL: POST /admin0363/bundles/new
# ================================
@app.route("/admin0363/bundles/new", methods=["POST"])
def admin_create_bundle():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    # ---- 基本欄位 ----
    form = request.form
    name         = (form.get("name") or "").strip()
    price_str    = (form.get("price") or "0").strip()
    price        = float(price_str) if price_str else 0.0
    compare_str  = (form.get("compare_at") or "").strip()
    compare_at   = float(compare_str) if compare_str else None
    stock        = int(form.get("stock") or 0)
    description  = (form.get("description") or "").strip()
    # ✅ 應選商品數量（0 代表不用逐步挑選模式）
    required_total = int(form.get("required_total") or 0)

    # 共用可選池（多選）
    pool_ids     = request.form.getlist("pool_ids[]")  # e.g. ["31","40","46"]
    # 動態 slots
    slot_labels  = request.form.getlist("slot_label[]")
    slot_counts  = request.form.getlist("slot_required[]")

    # ---- 封面圖上傳（Supabase Storage: images/bundle_images/…）----
    cover_image_url = None
    cover_image_file = request.files.get("cover_image")
    if cover_image_file and cover_image_file.filename:
        filename = secure_filename(cover_image_file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        storage_path = f"bundle_images/{unique_filename}"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cover_image_file.save(tmp.name)
            try:
                supabase.storage.from_("images").upload(storage_path, tmp.name)
                cover_image_url = supabase.storage.from_("images").get_public_url(storage_path)
            except Exception as e:
                print("❗️套組封面上傳錯誤：", e)

    # ---- 1) 建立 bundles 主檔（含 required_total）----
    inserted = (
        supabase.table("bundles")
        .insert({
            "name": name,
            "price": price,
            "compare_at": compare_at,
            "stock": stock,
            "cover_image": cover_image_url,
            "description": description,
            "active": True,
            "required_total": required_total,  # ✅ 新增欄位
        })
        .execute()
        .data
    )
    bundle_id = inserted[0]["id"]

    # ---- 2) 建立 slots + 每個 slot 的限定可選商品（bundle_slot_pool）----
    # 表單欄位命名規則：slot_pool_{index}[]，例如 slot_pool_0[]、slot_pool_1[] …
    slot_ids = []
    for idx, label in enumerate(slot_labels):
        cnt = int(slot_counts[idx] or 1) if idx < len(slot_counts) else 1
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
        slot_ids.append(slot_id)

        # 讀取此欄位的限定可選商品，多選；若留空＝沿用共用池（不必寫入 bundle_slot_pool）
        slot_pool_ids = request.form.getlist(f"slot_pool_{idx}[]")
        for pid in slot_pool_ids:
            try:
                supabase.table("bundle_slot_pool").insert({
                    "bundle_id": bundle_id,
                    "slot_id": slot_id,
                    "product_id": int(pid)
                }).execute()
            except Exception as e:
                print("❗️寫入 bundle_slot_pool 失敗：", idx, pid, e)

    # ---- 3) 建立共用可選池（bundle_pool）----
    for pid in pool_ids:
        try:
            supabase.table("bundle_pool").insert({
                "bundle_id": bundle_id,
                "product_id": int(pid)
            }).execute()
        except Exception as e:
            print("❗️寫入 bundle_pool 失敗：", pid, e)

    # ---- 4) 建立 products 殼品項，並回寫 bundles.shell_product_id ----
    try:
        shell_insert = (
            supabase.table("products")
            .insert({
                "name": f"[套組優惠] {name}",
                "price": price,
                "discount_price": None,
                "stock": stock,
                "image": cover_image_url,
                "images": [],
                "intro": description,
                "feature": "",
                "spec": "",
                "ingredient": "",
                "options": [],
                "categories": ["套組"],
                "tags": [],
                "product_type": "bundle"
            })
            .execute()
        )
        shell_product_id = shell_insert.data[0]["id"]

        # 回寫到 bundles.shell_product_id
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

    # 套組主檔
    b = (
        supabase.table("bundles")
        .select("*")
        .eq("id", bundle_id)
        .single()
        .execute()
        .data
    )
    if not b:
        return "找不到套組", 404

    # slots
    slots = (
        supabase.table("bundle_slots")
        .select("*")
        .eq("bundle_id", bundle_id)
        .order("slot_index")
        .execute()
        .data
        or []
    )

    # 共用可選池（bundle_pool）
    pool_rows = (
        supabase.table("bundle_pool")
        .select("product_id")
        .eq("bundle_id", bundle_id)
        .execute()
        .data
        or []
    )
    pool_ids = [r["product_id"] for r in pool_rows]

    # 各欄位限定可選商品（bundle_slot_pool）→ 做成 {slot_id: [product_id,...]}
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

    # 後台可選的單品清單（做為下拉選項）
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
        slot_pool_map=slot_pool_map,  # ✅ 讓模板能預先勾選每個欄位限定的商品
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
    name        = (form.get("name") or "").strip()
    price       = float(form.get("price") or 0)
    compare_at  = float(form.get("compare_at")) if form.get("compare_at") else None
    stock       = int(form.get("stock") or 0)
    description = (form.get("description") or "").strip()
    # ✅ 應選商品數量（0=不用逐步挑選模式）
    required_total = int(form.get("required_total") or 0)

    # 共用可選池
    pool_ids    = request.form.getlist("pool_ids[]")
    # 動態 slots
    slot_labels = request.form.getlist("slot_label[]")
    slot_counts = request.form.getlist("slot_required[]")

    # ---- 封面圖（可更新）----
    cover_image_url = None
    cover_image_file = request.files.get("cover_image")
    if cover_image_file and cover_image_file.filename:
        filename = secure_filename(cover_image_file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        storage_path = f"bundle_images/{unique_filename}"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cover_image_file.save(tmp.name)
            try:
                supabase.storage.from_("images").upload(storage_path, tmp.name)
                cover_image_url = supabase.storage.from_("images").get_public_url(storage_path)
            except Exception as e:
                print("❗️套組封面更新錯誤：", e)

    # ---- 1) 更新 bundles 主檔（含 required_total）----
    update_data = {
        "name": name,
        "price": price,
        "compare_at": compare_at,
        "stock": stock,
        "description": description,
        "required_total": required_total,   # ✅ 新增
    }
    if cover_image_url:
        update_data["cover_image"] = cover_image_url
    supabase.table("bundles").update(update_data).eq("id", bundle_id).execute()

    # ---- 2) 重建 slots 與每 slot 的限定商品（bundle_slot_pool）----
    # 先清空舊資料
    supabase.table("bundle_slots").delete().eq("bundle_id", bundle_id).execute()
    supabase.table("bundle_slot_pool").delete().eq("bundle_id", bundle_id).execute()

    for idx, label in enumerate(slot_labels):
        cnt = int(slot_counts[idx] or 1) if idx < len(slot_counts) else 1
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

        # 這個欄位的「限定可選商品」（留空＝沿用共用池，不需寫）
        slot_pool_ids = request.form.getlist(f"slot_pool_{idx}[]")
        for pid in slot_pool_ids:
            try:
                supabase.table("bundle_slot_pool").insert({
                    "bundle_id": bundle_id,
                    "slot_id": slot_id,
                    "product_id": int(pid)
                }).execute()
            except Exception as e:
                print("❗️寫入 bundle_slot_pool 失敗：", idx, pid, e)

    # ---- 3) 重建共用可選池（bundle_pool）----
    supabase.table("bundle_pool").delete().eq("bundle_id", bundle_id).execute()
    for pid in pool_ids:
        supabase.table("bundle_pool").insert({
            "bundle_id": bundle_id,
            "product_id": int(pid)
        }).execute()

    # ---- 4) 同步更新殼商品（名稱/價格/庫存/首圖）----
    b = (
        supabase.table("bundles")
        .select("shell_product_id")
        .eq("id", bundle_id)
        .single()
        .execute()
        .data
    )
    shell_id = b.get("shell_product_id") if b else None
    if shell_id:
        shell_update = {
            "name": f"[套組優惠] {name}",
            "price": price,
            "stock": stock,
            "intro": description
        }
        if cover_image_url:
            shell_update["image"] = cover_image_url
        supabase.table("products").update(shell_update).eq("id", shell_id).execute()

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
    if request.method == 'POST':
        action = request.form.get('action')
        product_id = request.form.get('product_id')
        option = (request.form.get('option') or '')
        cart = session.get('cart', [])

        for item in cart:
            if item.get('product_id') == product_id and (item.get('option') or '') == option:
                if action == 'increase':
                    item['qty'] += 1
                elif action == 'decrease' and item['qty'] > 1:
                    item['qty'] -= 1
                elif action == 'remove':
                    cart.remove(item)
                break

        session['cart'] = cart
        return redirect(url_for('cart'))

    # ---- GET：顯示購物車 ----
    cart_items = session.get('cart', [])
    products = []
    total = 0.0

    for item in cart_items:
        pid = item.get('product_id')
        if not pid:
            continue

        # 先讀購物車裡儲存的數值（加入購物車時已處理過單品/套組價格）
        unit_price = float(item.get('price') or 0)                 # 單價（計價用）
        unit_compare = float(item.get('original_price') or 0)      # 原價（顯示刪除線）
        unit_discount = float(item.get('discount_price') or 0)     # 折扣價（若有且 < 原價）
        qty = int(item.get('qty') or 1)

        # 從 DB 補商品基本資訊（名稱/圖），不覆蓋價格
        db = supabase.table("products").select("name,image,images,product_type") \
                     .eq("id", pid).single().execute()
        dbp = db.data or {}

        # 圖片：先用購物車存的，其次 DB
        images = item.get('images') or dbp.get('images') or []
        image = item.get('image') or dbp.get('image') \
                or (images[0] if images else None)

        product_out = {
            'id': pid,
            'name': dbp.get('name') or item.get('name'),
            'product_type': item.get('product_type') or dbp.get('product_type'),

            # ✅ 把 bundle 欄位帶到模板
            'bundle_price':   item.get('bundle_price'),
            'bundle_compare': item.get('bundle_compare'),

            # 前端顯示/計算會用到的欄位
            'price': unit_price,
            'original_price': unit_compare if unit_compare > 0 else unit_price,
            'discount_price': unit_discount if (unit_discount and unit_compare and unit_discount < unit_compare) else 0.0,
            'qty': qty,
            'subtotal': unit_price * qty,

            'option': item.get('option', ''),
            'image': image,
            'images': images,
        }

        products.append(product_out)
        total += product_out['subtotal']

    shipping_fee = 0 if total >= 2000 else 80
    final_total = total + shipping_fee
    free_shipping_diff = 0 if total >= 2000 else (2000 - total)

    return render_template(
        "cart.html",
        products=products,
        total=total,
        shipping_fee=shipping_fee,
        final_total=final_total,
        free_shipping_diff=free_shipping_diff
    )





#結帳
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
    total = 0
    items = []

    for item in cart_items:
        # 撈出當前商品資訊（但只拿必要資訊）
        res = supabase.table("products").select("id,name,price,discount_price").eq("id", item['product_id']).single().execute()
        product = res.data
        if product:
            # ✅ 優先使用購物車中記錄的價格
            item_price = item.get('price') or product.get('discount_price') or product['price']
            qty = item.get('qty', 1)
            subtotal = item_price * qty
            total += subtotal

            items.append({
                'product_id': str(product['id']),
                'product_name': product['name'],
                'qty': qty,
                'price': item_price,
                'subtotal': subtotal,
                'option': item.get('option', '')
            })

    # ✅ 運費判斷
    shipping_fee = 0 if total >= 2000 else 80
    final_total = total + shipping_fee

    from uuid import uuid4
    from pytz import timezone
    from datetime import datetime
    tz = timezone("Asia/Taipei")
    merchant_trade_no = "HS" + uuid4().hex[:12]
    created_at = datetime.now(tz).isoformat()

    # ✅ 建立訂單資料
    order_data = {
        'member_id': member_id,
        'total_amount': final_total,
        'shipping_fee': shipping_fee,
        'status': 'pending',
        'created_at': created_at,
        'MerchantTradeNo': merchant_trade_no
    }
    result = supabase.table('orders').insert(order_data).execute()
    order_id = result.data[0]['id']

    # ✅ 寫入每筆商品明細
    for item in items:
        item['id'] = str(uuid4())
        item['order_id'] = order_id
        item['option'] = item.get('option', '')

    supabase.table('order_items').insert(items).execute()

    # ✅ 清空購物車
    session['cart'] = []

    # ✅ 暫存交易編號（後續綠界付款用）
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
    

#line pay結帳
@app.route("/linepay")
def linepay():
    return render_template("linepay.html")

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




#判斷用戶選的付款方式
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
        return render_template("linepay.html", order=order)  # 顯示 QR 碼或帳號資訊

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
    # 先抓商品
    res = supabase.table("products").select("*").eq("id", product_id).single().execute()
    product = res.data
    if not product:
        return "找不到商品", 404

    cart = session.get('cart', [])
    cart_count = sum(item['qty'] for item in cart)

    # 預設值（避免未定義）
    bundle = None
    slots = []              # 已停用 slots，但保留給模板相容
    pool_products = []
    slot_allowed = {}       # 已停用 slots，但保留給模板相容
    total_mode = False
    required_total = 0

    # 套組殼商品：採用 required_total + pool 模式
    if product.get('product_type') == 'bundle':
        bres = (
            supabase.table("bundles")
            .select("*")
            .eq("shell_product_id", product["id"])
            .single()
            .execute()
        )
        bundle = bres.data or None

        if bundle:
            required_total = int(bundle.get("required_total") or 0)
            total_mode = required_total > 0

            # 共用可選池
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

    return render_template(
        "product.html",
        product=product,
        cart_count=cart_count,
        bundle=bundle,
        slots=slots,
        pool_products=pool_products,
        slot_allowed=slot_allowed,
        total_mode=total_mode,         # ✅ 已定義
        required_total=required_total  # ✅ 已定義
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
        order_result = supabase.table("orders").select("*").eq("merchant_trade_no", merchant_trade_no).execute()

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
    

    from pytz import timezone
    from dateutil import parser
    tz = timezone("Asia/Taipei")

    for m in members:
        try:
            utc_dt = parser.parse(m['created_at'])
            m['created_at'] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except:
            m['created_at'] = m.get('created_at', '—')

    # 🔧 避免 template 出錯，加上預設變數
    return render_template("admin.html",
        tab="members",
        products=[],
        orders=[],
        members=members,
        messages=[],
        product_page=0,
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

        # ✅ 新增：處理優惠價欄位
        discount_price_str = request.form.get("discount_price", "").strip()
        discount_price = float(discount_price_str) if discount_price_str else None

        stock_str = request.form.get('stock', '0').strip()
        stock = int(stock_str) if stock_str else 0
        intro = request.form.get('intro', '').strip()
        feature = request.form.get('feature', '').strip()
        spec = request.form.get('spec', '').strip()
        ingredient = request.form.get('ingredient', '').strip()
        categories = request.form.getlist('categories[]')
        tags = request.form.getlist('tags')  # ✅ 取得多選標籤
        options = request.form.getlist('options[]')

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

        if not cover_url:
            return "請上傳商品首頁主圖", 400

        # ✅ 建立商品資料（含優惠價）
        data = {
            "name": name,
            "price": price,
            "discount_price": discount_price,  # ✅ 新增欄位
            "stock": stock,
            "image": cover_url,
            "images": image_urls,
            "intro": intro,
            "feature": feature,
            "spec": spec,
            "ingredient": ingredient,
            "options": options,
            "categories": categories,
            "tags": tags
        }

        response = supabase.table("products").insert(data).execute()

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
            updated = {
                "name": request.form.get('name', '').strip(),
                "price": float(request.form.get('price', '0').strip()),
                "discount_price": float(request.form.get('discount_price').strip()) if request.form.get('discount_price') else None,
                "stock": int(request.form.get('stock', '0').strip() or 0),
                "intro": request.form.get('intro', '').strip(),
                "feature": request.form.get('feature', '').strip(),
                "spec": request.form.get('spec', '').strip(),
                "ingredient": request.form.get('ingredient', '').strip(),
                "options": request.form.getlist('options[]'),
                "categories": request.form.getlist('categories[]'),
                "tags": request.form.getlist('tags')
            }

            # ✅ 主圖處理
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
                existing_cover = request.form.get("existing_cover_image")
                if existing_cover:
                    updated["image"] = existing_cover

            # ✅ 其餘圖片處理
            kept_images = request.form.getlist("existing_images[]")
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

            updated['images'] = kept_images + image_urls
            if 'image' not in updated and updated['images']:
                updated['image'] = updated['images'][0]

            supabase.table("products").update(updated).eq("id", product_id).execute()
            return redirect('/admin0363/dashboard?tab=products')

        except Exception as e:
            return f"編輯商品時發生錯誤：{str(e)}", 500

    else:
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
@app.route('/profile', methods=['POST'])
def save_profile():
    if 'member_id' not in session:
        return jsonify(success=False, message="Not logged in"), 401

    try:
        # 轉型，確保是正確的 uuid
        member_id = str(UUID(session['member_id']))
    except Exception:
        return jsonify(success=False, message="Invalid member_id in session"), 400

    name    = (request.form.get('name') or '').strip()
    phone   = (request.form.get('phone') or '').strip()
    address = (request.form.get('address') or '').strip()
    note    = (request.form.get('note') or '').strip()

    try:
        res = (
            supabase.table("members")
            .update({
                "name": name,
                "phone": phone,
                "address": address,
                "note": note
            })
            .eq("id", member_id)   # 這裡傳進去就是合法 uuid 字串
            .select("*")
            .execute()
        )

        if not res.data:
            return jsonify(success=False, message="Member not found"), 404

        session.pop('incomplete_profile', None)

        return jsonify(success=True, message="Profile updated successfully"), 200

    except Exception as e:
        return jsonify(success=False, message=str(e)), 500



# 會員歷史訂單路由
@app.route('/order/<int:order_id>')
def order_detail(order_id):
    from pytz import timezone
    from dateutil import parser
    tz = timezone("Asia/Taipei")

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
    tz = timezone("Asia/Taipei")

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
from datetime import datetime

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

    tz = timezone("Asia/Taipei")
    member_id = session["member_id"]
    page = int(request.args.get("page", 1))
    per_page = 5

    # 全部留言（新 → 舊）
    all_messages = supabase.table("messages") \
        .select("*") \
        .eq("member_id", member_id) \
        .order("created_at", desc=True) \
        .execute().data or []

    # 顯示台灣時間 & 是否為新回覆
    for m in all_messages:
        try:
            m["local_created_at"] = parser.parse(m["created_at"]).astimezone(tz).strftime("%Y-%m-%d %H:%M")
        except:
            m["local_created_at"] = m["created_at"]
        m["is_new"] = m.get("is_replied") and not m.get("is_read")

    # 分頁
    total = len(all_messages)
    start = (page - 1) * per_page
    end = start + per_page
    messages = all_messages[start:end]
    has_prev = page > 1
    has_next = end < total

    # 設為已讀
    if messages:
        supabase.table("messages") \
            .update({"is_read": True}) \
            .eq("member_id", member_id) \
            .eq("is_replied", True) \
            .eq("is_read", False) \
            .execute()

    session["has_new_reply"] = False

    return render_template("member_messages.html",
                           messages=messages,
                           page=page,
                           has_prev=has_prev,
                           has_next=has_next)





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
