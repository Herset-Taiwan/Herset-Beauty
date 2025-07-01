from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from werkzeug.utils import secure_filename
from supabase import create_client, Client
import os
import tempfile
import uuid
from dotenv import load_dotenv
from datetime import datetime
from uuid import UUID
from flask import flash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.route('/')
def index():
    res = supabase.table("products").select("*").execute()
    products = res.data
    cart = session.get('cart', [])
    cart_count = sum(item['qty'] for item in cart)
    return render_template("index.html", products=products, cart_count=cart_count)

@app.route('/login', methods=['GET', 'POST'])
def login():
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
             session['member_id'] = res.data[0]['id']  # 🟢 這行非常重要！
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
                "created_at": datetime.utcnow().isoformat()
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

@app.route('/cart', methods=['GET', 'POST'])
def cart():
    if request.method == 'POST':
        action = request.form.get('action')
        product_id = int(request.form.get('product_id'))
        cart = session.get('cart', [])
        for item in cart:
            if item['product_id'] == product_id:
                if action == 'increase':
                    item['qty'] += 1
                elif action == 'decrease' and item['qty'] > 1:
                    item['qty'] -= 1
                elif action == 'remove':
                    cart.remove(item)
                break
        session['cart'] = cart
        return redirect(url_for('cart'))

    cart_items = session.get('cart', [])
    products = []
    total = 0
    for item in cart_items:
        res = supabase.table("products").select("*").eq("id", item['product_id']).single().execute()
        if res.data:
            product = res.data
            product['qty'] = item['qty']
            product['subtotal'] = item['qty'] * product['price']
            total += product['subtotal']
            products.append(product)
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
        'created_at': datetime.utcnow().isoformat()
    }
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

@app.route('/admin/orders/update/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    new_status = request.form.get("status")
    if new_status:
        supabase.table("orders").update({"status": new_status}).eq("id", order_id).execute()
    return redirect("/admin")

@app.route('/product/<int:product_id>')
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
    products = supabase.table("products").select("*").execute().data
    members = supabase.table("members").select("id, username, account, phone, email").limit(10).execute().data
    orders = supabase.table("orders").select("*").order("created_at", desc=True).limit(20).execute().data
    return render_template("admin.html", products=products, members=members, orders=orders)


@app.route('/admin/members')
def search_members():
    keyword = request.args.get("keyword", "").strip()
    query = supabase.table("members").select("id, username, account, phone, email")
    if keyword:
        query = query.or_(
            f"account.ilike.%{keyword}%,username.ilike.%{keyword}%,phone.ilike.%{keyword}%,email.ilike.%{keyword}%"
        )
    members = query.execute().data
    products = []
    orders = []
    return render_template("admin.html", products=products, members=members, orders=orders)

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
                filename = secure_filename(file.filename)
                storage_path = f"product_images/{filename}"
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    file.save(tmp.name)
                    try:
                        supabase.storage.from_("images").upload(storage_path, tmp.name)
                    except Exception as e:
                        print("❗️圖片上傳錯誤：", e)
                url = supabase.storage.from_("images").get_public_url(storage_path)
                image_urls.append(url)

        options = request.form.getlist('options[]')

        data = {
            "name": name,
            "price": price,
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

        return redirect('/admin')

    except Exception as e:
        print("🚨 新增商品錯誤：", e)
        return f"新增商品時發生錯誤：{str(e)}", 500

@app.route('/edit/<int:product_id>', methods=['GET', 'POST'])
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

        image_files = request.files.getlist("image_files")
        image_urls = []
        for file in image_files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                storage_path = f"product_images/{filename}"
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    file.save(tmp.name)
                    try:
                        supabase.storage.from_("images").upload(storage_path, tmp.name)
                    except Exception as e:
                        print("❗️圖片上傳錯誤：", e)
                url = supabase.storage.from_("images").get_public_url(storage_path)
                image_urls.append(url)
        if image_urls:
            updated['images'] = image_urls

        supabase.table("products").update(updated).eq("id", product_id).execute()
        return redirect('/admin')
    else:
        res = supabase.table("products").select("*").eq("id", product_id).single().execute()
        product = res.data
        if not product:
            return "找不到商品", 404
        return render_template("edit_product.html", product=product)

@app.route('/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    supabase.table("products").delete().eq("id", product_id).execute()
    return redirect('/admin')

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_id = int(request.form['product_id'])
    res = supabase.table("products").select("*").eq("id", product_id).single().execute()
    if not res.data:
        return jsonify(success=False)

    product = res.data
    cart = session.get('cart', [])
    for item in cart:
        if item['product_id'] == product_id:
            item['qty'] += 1
            break
    else:
        cart.append({
            'product_id': product_id,
            'name': product['name'],
            'price': product['price'],
            'qty': 1
        })
    session['cart'] = cart
    print("🛒 當前購物車：", cart)
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

    return redirect('/')

@app.route('/profile-data')
def profile_data():
    if 'member_id' not in session:
        return jsonify(success=False, message="Not logged in")

    member_id = session['member_id']
    res = supabase.table("members").select("name, phone, address, note").eq("id", member_id).execute()

    if not res.data:
        return jsonify(success=False, message="No data found")

    return jsonify(success=True, data=res.data[0])




if __name__ == '__main__':
    app.run(debug=True)
