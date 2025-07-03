from pytz import timezone
from datetime import datetime
from dateutil import parser

from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
from werkzeug.utils import secure_filename
from supabase import create_client, Client
from flask_mail import Mail, Message
import os
import tempfile
import uuid
from dotenv import load_dotenv
from uuid import UUID

load_dotenv()

app = Flask(__name__)
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


# ✅ 忘記密碼 - 輸入電話與信箱
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        phone = request.form['phone']
        email = request.form['email']
        res = supabase.table("users").select("*").eq("phone", phone).eq("email", email).execute()
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

# ✅ 驗證碼確認
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        code_input = request.form['code']
        if code_input == session.get('reset_code'):
            user = session.get('reset_user')
            flash(f"您的密碼為：{user['password']}", "success")
            session.pop('reset_code', None)
            session.pop('reset_user', None)
            return redirect("/login")
        else:
            flash("驗證碼錯誤，請重新輸入。", "danger")
    return render_template("verify.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_page = request.args.get('next')  # 例如 cart

    if request.method == 'POST':
        account = request.form.get('account')
        password = request.form.get('password')

        if not account or not password:
            return render_template("login.html", error="請輸入帳號與密碼")

        res = supabase.table("members") \
            .select("id, account, password") \
            .eq("account", account).execute()

        if res.data and res.data[0]['password'] == password:
            session['user'] = res.data[0]
            session['member_id'] = res.data[0]['id']

            # ✅ 根據 next 決定跳轉頁面
            if next_page == 'cart':
                return redirect('/cart')
            else:
                return redirect('/')

        else:
            return render_template("login.html", error="帳號或密碼錯誤")

    return render_template("login.html")




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
            # 加入防呆：有些舊資料可能是 'id' 而不是 'product_id'
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
            continue  # 避免錯誤

        res = supabase.table("products").select("*").eq("id", pid).single().execute()
        if res.data:
            product = res.data
            product['qty'] = item.get('qty', 1)
            product['subtotal'] = product['qty'] * product['price']
            products.append(product)
            total += product['subtotal']

    return render_template("cart.html", products=products, total=total)



@app.route('/checkout', methods=['POST'])
def checkout():
    # ✅ 檢查是否已登入會員（有 member_id）
    if 'member_id' not in session:
        flash("請先登入會員才能結帳")
        return redirect('/cart')

    cart_items = session.get('cart', [])
    if not cart_items:
        return redirect('/cart')

    member_id = session.get('member_id')
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

    order_data = {
        'member_id': member_id,
        'total_amount': total,
        'status': 'pending',
        'created_at': datetime.now(tz).isoformat()
    }
    print("✅ 寫入的訂單時間（台灣時間）:", order_data['created_at'])
    print("✅ order_data：", order_data)
    result = supabase.table('orders').insert(order_data).execute()
    order_id = result.data[0]['id']

    for item in items:
        item['order_id'] = order_id
    supabase.table('order_items').insert(items).execute()

    session['cart'] = []
    return redirect(url_for('thank_you'))

@app.route('/thank-you')
def thank_you():
    return render_template("thank_you.html")

@app.route('/admin/orders/update_status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    new_status = request.form.get("status")
    if new_status:
        supabase.table("orders").update({"status": new_status}).eq("id", order_id).execute()
        flash("訂單狀態已修改")
    return redirect("/admin?tab=orders")



@app.route('/product/<product_id>')
def product_detail(product_id):

    res = supabase.table("products").select("*").eq("id", product_id).single().execute()
    product = res.data
    if not product:
        return "找不到商品", 404
    cart = session.get('cart', [])
    cart_count = sum(item['qty'] for item in cart)
    return render_template("product.html", product=product, cart_count=cart_count)

@app.route('/admin')
def admin():
    from pytz import timezone
    from dateutil import parser
    tz = timezone("Asia/Taipei")

    tab = request.args.get("tab", "products")  # 🟢 預設 tab

    # 查詢商品
    res = supabase.table("products").select("*").execute()
    if hasattr(res, 'error') and res.error:
        print("❌ 商品查詢失敗：", res.error)
        products = []
    else:
        products = res.data or []
    print("✅ 商品筆數：", len(products))

    # 查詢訂單
    res = supabase.table("orders").select("*").order("created_at", desc=True).execute()
    orders_raw = res.data or []

    # 查詢會員（補上 created_at）
    res = supabase.table("members").select("id, account, username, name, phone, email, address, note, created_at").execute()
    members = res.data or []

    # 🟢 加入會員註冊時間轉換
    for m in members:
        try:
            if 'created_at' in m and m['created_at']:
                utc_dt = parser.parse(m['created_at'])
                m['created_at'] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            print("⚠️ 會員註冊時間轉換錯誤：", m.get('created_at'), e)
            m['created_at'] = m.get('created_at') or '—'

    member_dict = {m['id']: m for m in members}

    # 查詢訂單項目
    res = supabase.table("order_items").select("*").execute()
    items = res.data or []
    item_group = {}
    for item in items:
        item_group.setdefault(item['order_id'], []).append(item)

    # 整合訂單資料
    orders = []
    for o in orders_raw:
        o['items'] = item_group.get(o['id'], [])

        member = member_dict.get(o['member_id'])
        o['member'] = {
            'account': member['account'] if member else 'guest',
            'name': member['name'] if member and 'name' in member else '訪客',
            'phone': member['phone'] if member and 'phone' in member else '—',
            'address': member['address'] if member and 'address' in member else '—',
        }

        try:
            utc_dt = parser.parse(o['created_at'])
            o['created_local'] = utc_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            print("⚠️ 訂單時間轉換錯誤：", o['created_at'], e)
            o['created_local'] = o['created_at']

        orders.append(o)

    return render_template("admin.html", products=products, members=members, orders=orders, tab=tab)



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



@app.route('/admin/orders/delete/<int:order_id>', methods=['POST'])
def delete_order(order_id):
    supabase.table("orders").delete().eq("id", order_id).execute()
    supabase.table("order_items").delete().eq("order_id", order_id).execute()  # 一併清除
    return redirect('/admin')


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
        category = request.form.get('category', '').strip()

        image_files = request.files.getlist("image_files")
        image_urls = []
        for file in image_files:
            if file and file.filename:
                # ✅ 自動加上 UUID 前綴避免檔名重複
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                storage_path = f"product_images/{unique_filename}"

                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    file.save(tmp.name)
                    try:
                        supabase.storage.from_("images").upload(storage_path, tmp.name)
                    except Exception as e:
                        print("❗️圖片上傳錯誤：", e)
                        continue  # 跳過失敗圖片

                url = supabase.storage.from_("images").get_public_url(storage_path)
                image_urls.append(url)

        # ✅ 確保至少有一張主圖片
        if not image_urls:
            return "請上傳至少一張圖片", 400

        options = request.form.getlist('options[]')

        data = {
            "name": name,
            "price": price,
            "image": image_urls[0],  # ✅ 這是主圖片，必要欄位
            "images": image_urls,
            "intro": intro,
            "feature": feature,
            "spec": spec,
            "ingredient": ingredient,
            "options": options,
            "category": category
        }

        print("📤 準備插入資料：", data)
        response = supabase.table("products").insert(data).execute()
        print("📥 插入結果：", response)

        if hasattr(response, 'error') and response.error:
            print("⚠️ Supabase 錯誤：", response.error)
            return f"資料寫入失敗：{response.error['message']}", 500

        return redirect('/admin?tab=products')  # 回商品頁籤

    except Exception as e:
        print("🚨 新增商品錯誤：", e)
        return f"新增商品時發生錯誤：{str(e)}", 500


@app.route('/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if request.method == 'POST':
        updated = {
            "name": request.form['name'],
            "price": float(request.form['price']),
            "intro": request.form['intro'],
            "feature": request.form['feature'],
            "spec": request.form['spec'],
            "ingredient": request.form['ingredient'],
            "options": request.form.getlist('options[]'),
            "category": request.form.get('category', '')
        }

        # ✅ 使用者保留的舊圖
        kept_images = request.form.getlist('existing_images[]')

        # ✅ 新上傳的圖片
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

        # ✅ 設定主圖為第一張
        if updated['images']:
            updated['image'] = updated['images'][0]

        # ✅ 寫入資料庫
        supabase.table("products").update(updated).eq("id", product_id).execute()
        return redirect('/admin?tab=products')

    else:
        # GET：載入原始商品
        res = supabase.table("products").select("*").eq("id", product_id).single().execute()
        product = res.data
        if not product:
            return "找不到商品", 404
        return render_template("edit_product.html", product=product)



@app.route('/delete/<product_id>', methods=['POST'])
def delete_product(product_id):

    supabase.table("products").delete().eq("id", product_id).execute()
    return redirect('/admin')

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

# 忘記密碼路由
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    message = ''
    if request.method == 'POST':
        phone = request.form['phone']
        email = request.form['email']
        # 假設使用 Supabase 查詢會員資料
        res = supabase.table('users').select("*").eq("phone", phone).eq("email", email).execute()
        users = res.data
        if users:
            password = users[0]['password']
            message = f"您的密碼是：{password}"
        else:
            message = "查無此帳號資料，請確認輸入的電話與 Email 是否正確。"
    return render_template("forgot.html", message=message)





if __name__ == '__main__':
    app.run(debug=True)
