from pytz import timezone
from pytz import timezone
tz = timezone("Asia/Taipei")
from flask import request
from datetime import datetime
from dateutil import parser
from flask import send_from_directory

from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
from werkzeug.utils import secure_filename
from supabase import create_client, Client
from flask_mail import Mail, Message
import os
import tempfile
import uuid
from dotenv import load_dotenv
from uuid import UUID
import urllib.parse
import hashlib
import random
import datetime
import time
from utils import generate_check_mac_value
from datetime import datetime
from utils import generate_check_mac_value, generate_ecpay_form
from utils import generate_ecpay_form
from uuid import uuid4
from flask import Response
from flask import request, render_template, Response
from flask import render_template, session, redirect


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

@app.route('/')
def index():
    category = request.args.get('category')  # 抓網址的 category 參數
    res = supabase.table("products").select("*").execute()
    products = res.data

    # ✅ 篩選分類（如果有傳入且不是「全部」）
    if category and category != '全部':
        products = [p for p in products if p.get('category') == category]

    cart = session.get('cart', [])
    cart_count = sum(item['qty'] for item in cart)
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



# 後台登入畫面（網址：https://herset.co/admin0363）
@app.route("/admin0363", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect("/admin0363/dashboard")
        else:
            return render_template("admin_login.html", error="帳號或密碼錯誤")
    return render_template("admin_login.html")

@app.route("/admin0363/dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    from pytz import timezone
    from dateutil import parser
    import json

    tz = timezone("Asia/Taipei")
    tab = request.args.get("tab", "products")
    selected_categories = request.args.getlist("category")

    # ✅ 商品（預設顯示全部，有勾分類才篩選）
    if tab == "products":
        query = supabase.table("products").select("*")
        if selected_categories:
            filters = [f"categories.cs.{json.dumps([cat])}" for cat in selected_categories]
            query = query.or_(','.join(filters))
        products = query.execute().data or []
    else:
        products = []

    # ✅ 會員
    members = supabase.table("members").select(
        "id, account, username, name, phone, email, address, note, created_at"
    ).execute().data or []

    for m in members:
        try:
            if m.get("created_at"):
                utc_dt = parser.parse(m["created_at"])
                m["created_at"] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except:
            m["created_at"] = m.get("created_at", "—")

    member_dict = {m["id"]: m for m in members}

    # ✅ 訂單
    orders_raw = supabase.table("orders").select("*").order("created_at", desc=True).execute().data or []
    order_items = supabase.table("order_items").select("*").execute().data or []

    item_group = {}
    for item in order_items:
        item_group.setdefault(item["order_id"], []).append(item)

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
        try:
            utc_dt = parser.parse(o["created_at"])
            o["created_local"] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except:
            o["created_local"] = o["created_at"]

        orders.append(o)

    return render_template("admin.html",
                           products=products,
                           members=members,
                           orders=orders,
                           tab=tab,
                           selected_categories=selected_categories)




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
        return jsonify({})  # 未登入就回空物件

    member_id = str(UUID(session['member_id']))
    res = supabase.table("members").select("name, phone, address, note").eq("id", member_id).execute()

    if res.data:
        return jsonify(res.data[0])
    else:
        return jsonify({})



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        account = request.form['account']
        email = request.form['email']
        password = request.form['password']
        username = account

        # 檢查帳號是否已存在
        exist = supabase.table("members").select("account").eq("account", account).execute()
        if exist.data:
            return render_template("register.html", error="此帳號已被使用")

        try:
            # 不給 id，讓 Supabase 自動產生
            response = supabase.table("members").insert({
                "account": account,
                "email": email,
                "password": password,
                "username": username,
                "created_at": datetime.now(tz).isoformat()
            }).execute()

            # 🔍 印出結果確認
            print("✅ 註冊成功：", response)

            # 直接登入（可選）
            session['user'] = {
                'account': account,
                'email': email
            }
            session['member_id'] = response.data[0]['id']  # 🟢 儲存真正由 Supabase 產生的 ID

            return render_template("register_success.html")

        except Exception as e:
            print("🚨 註冊錯誤：", e)
            return render_template("register.html", error="註冊失敗，請稍後再試")

    return render_template("register.html")




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
        cart = session.get('cart', [])

        for item in cart:
            pid = item.get('product_id') or item.get('id')
            if pid == product_id:
                if action == 'increase':
                    item['qty'] += 1
                elif action == 'decrease' and item['qty'] > 1:
                    item['qty'] -= 1
                elif action == 'remove':
                    cart.remove(item)
                break

        session['cart'] = cart
        return redirect(url_for('cart'))

    # GET 顯示購物車內容
    cart_items = session.get('cart', [])
    products = []
    total = 0

    for item in cart_items:
        pid = item.get('product_id') or item.get('id')
        if not pid:
            continue

        res = supabase.table("products").select("*").eq("id", pid).single().execute()
        if res.data:
            product = res.data
            product['qty'] = item.get('qty', 1)
            product['subtotal'] = product['qty'] * product['price']
            products.append(product)
            total += product['subtotal']

    # 運費邏輯
    shipping_fee = 0 if total >= 2000 else 80
    final_total = total + shipping_fee
    free_shipping_diff = 0 if total >= 2000 else 2000 - total

    return render_template("cart.html",
                           products=products,
                           total=total,
                           shipping_fee=shipping_fee,
                           final_total=final_total,
                           free_shipping_diff=free_shipping_diff)


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
        res = supabase.table("products").select("*").eq("id", item['product_id']).single().execute()
        product = res.data
        if product:
            subtotal = item['qty'] * product['price']
            total += subtotal
            items.append({
                'product_id': str(product['id']),
                'product_name': product['name'],
                'qty': item['qty'],
                'price': product['price'],
                'subtotal': subtotal
            })

    # 加入運費判斷
    shipping_fee = 0 if total >= 2000 else 80
    final_total = total + shipping_fee

    from uuid import uuid4
    from pytz import timezone
    tz = timezone("Asia/Taipei")
    merchant_trade_no = "HS" + uuid4().hex[:12]
    created_at = datetime.now(tz).isoformat()

    order_data = {
        'member_id': member_id,
        'total_amount': final_total,
        'shipping_fee': shipping_fee,  # ← 若你的 orders 表沒有這欄位，可拿掉
        'status': 'pending',
        'created_at': created_at,
        'MerchantTradeNo': merchant_trade_no
    }
    result = supabase.table('orders').insert(order_data).execute()
    order_id = result.data[0]['id']

    for item in items:
        item['id'] = str(uuid4())             # ✅ 每筆都給一個唯一的 id
        item['order_id'] = order_id
    supabase.table('order_items').insert(items).execute()

    # 清空購物車
    session['cart'] = []

    # 暫存 trade_no 準備付款用
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

@app.route('/admin0363/orders/update_status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    new_status = request.form.get("status")
    if new_status:
        supabase.table("orders").update({"status": new_status}).eq("id", order_id).execute()
        flash("訂單狀態已修改")
    return redirect("/admin0363/dashboard?tab=orders")





@app.route('/product/<product_id>')
def product_detail(product_id):

    res = supabase.table("products").select("*").eq("id", product_id).single().execute()
    product = res.data
    if not product:
        return "找不到商品", 404
    cart = session.get('cart', [])
    cart_count = sum(item['qty'] for item in cart)
    return render_template("product.html", product=product, cart_count=cart_count)


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

    return "1|OK"  # 綠界固定格式，代表成功處理





#封鎖 /admin 的舊路由
@app.route('/admin')
def block_admin_shortcut():
    return "404 Not Found    The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.", 403


@app.route('/admin/members')
def search_members():
    keyword = request.args.get("keyword", "").strip()
    query = supabase.table("members").select("id, username, account, phone, email, address, note, created_at")
    if keyword:
        query = query.or_(
            f"account.ilike.%{keyword}%,username.ilike.%{keyword}%,phone.ilike.%{keyword}%,email.ilike.%{keyword}%"
        )
    members = query.execute().data

    # 🟢 加入註冊時間格式處理
    from pytz import timezone
    from dateutil import parser
    tz = timezone("Asia/Taipei")
    for m in members:
        try:
            utc_dt = parser.parse(m['created_at'])
            m['created_local'] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except:
            m['created_local'] = m.get('created_at', '—')

    # 補上其他頁籤資料
    products = supabase.table("products").select("*").execute().data or []

    res = supabase.table("orders").select("*").order("created_at", desc=True).execute()
    orders_raw = res.data or []
    res = supabase.table("order_items").select("*").execute()
    items = res.data or []
    item_group = {}
    for item in items:
        item_group.setdefault(item['order_id'], []).append(item)

    res = supabase.table("members").select("*").execute()
    member_dict = {m['id']: m for m in res.data or []}

    orders = []
    for o in orders_raw:
        o['items'] = item_group.get(o['id'], [])
        member = member_dict.get(o['member_id'])
        o['member'] = {
            'account': member['account'] if member else 'guest',
            'name': member.get('name') if member else '訪客',
            'phone': member.get('phone') if member else '—',
            'address': member.get('address') if member else '—'
        }
        try:
            utc_dt = parser.parse(o['created_at'])
            o['created_local'] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except:
            o['created_local'] = o['created_at']

        orders.append(o)

    return render_template("admin.html", products=products, members=members, orders=orders, tab="members")


#刪除訂單
@app.route('/admin0363/orders/delete/<int:order_id>', methods=['POST'])
def delete_order(order_id):
    supabase.table("orders").delete().eq("id", order_id).execute()
    supabase.table("order_items").delete().eq("order_id", order_id).execute()
    return redirect('/admin0363/dashboard')



@app.route('/admin/new')
def new_product():
    return render_template("new_product.html")


@app.route('/add_product', methods=['POST'])
def add_product():
    try:
        name = request.form.get('name', '').strip()
        price_str = request.form.get('price', '0').strip()
        price = float(price_str) if price_str else 0.0
        intro = request.form.get('intro', '').strip()
        feature = request.form.get('feature', '').strip()
        spec = request.form.get('spec', '').strip()
        ingredient = request.form.get('ingredient', '').strip()
        categories = request.form.getlist('categories[]')  # ✅ 多分類
        options = request.form.getlist('options[]')

        # ✅ 上傳圖片處理
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
                    except Exception as e:
                        print("❗️圖片上傳錯誤：", e)
                        continue
                url = supabase.storage.from_("images").get_public_url(storage_path)
                image_urls.append(url)

        if not image_urls:
            return "請上傳至少一張圖片", 400

        # ✅ 建立商品資料
        data = {
            "name": name,
            "price": price,
            "image": image_urls[0],
            "images": image_urls,
            "intro": intro,
            "feature": feature,
            "spec": spec,
            "ingredient": ingredient,
            "options": options,
            "categories": categories
        }

        response = supabase.table("products").insert(data).execute()

        if hasattr(response, 'error') and response.error:
            return f"資料寫入失敗：{response.error['message']}", 500

        return redirect('/admin0363/dashboard?tab=products')

    except Exception as e:
        return f"新增商品時發生錯誤：{str(e)}", 500


@app.route('/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if request.method == 'POST':
        try:
            updated = {
                "name": request.form.get('name', '').strip(),
                "price": float(request.form.get('price', '0').strip()),
                "intro": request.form.get('intro', '').strip(),
                "feature": request.form.get('feature', '').strip(),
                "spec": request.form.get('spec', '').strip(),
                "ingredient": request.form.get('ingredient', '').strip(),
                "options": request.form.getlist('options[]'),
                "categories": request.form.getlist('categories[]')
            }

            # ✅ 保留舊圖
            kept_images = request.form.getlist('existing_images[]')

            # ✅ 處理新上傳圖
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
                        except Exception as e:
                            print("❗️圖片上傳錯誤：", e)
                            continue
                    url = supabase.storage.from_("images").get_public_url(storage_path)
                    image_urls.append(url)

            # ✅ 合併舊圖與新圖
            updated['images'] = kept_images + image_urls
            if updated['images']:
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





@app.route('/delete/<product_id>', methods=['POST'])
def delete_product(product_id):

    supabase.table("products").delete().eq("id", product_id).execute()
    return redirect('/admin0363/dashboard')

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_id = request.form.get('product_id')
    qty = int(request.form.get('qty', 1))
    action = request.form.get('action')  # 👈 新增這一行

    # 找商品
    res = supabase.table('products').select('*').eq('id', product_id).execute()
    if not res.data:
        return jsonify(success=False), 404
    product = res.data[0]

    # 初始化購物車
    if 'cart' not in session:
        session['cart'] = []

    cart = session['cart']

    # 檢查是否已存在
    found = False
    for item in cart:
        if item.get('product_id') == product_id:
            item['qty'] += qty
            found = True
            break

    if not found:
        cart.append({
            'product_id': product_id,
            'name': product['name'],
            'price': product['price'],
            'images': product['images'],
            'qty': qty
        })

    session['cart'] = cart

    # ✅ 若是立即結帳就 redirect
    if action == 'checkout':
        return redirect('/cart')

    # AJAX 呼叫就回傳 JSON
    return jsonify(success=True, count=sum(item['qty'] for item in cart))




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

from flask import redirect

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




if __name__ == '__main__':
    app.run(debug=True)
