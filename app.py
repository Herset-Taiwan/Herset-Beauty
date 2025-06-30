from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from werkzeug.utils import secure_filename
from supabase import create_client, Client
import os
import tempfile
from dotenv import load_dotenv

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

@app.route('/login')
def login():
    return render_template("login.html")

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
    cart_items = session.pop('cart', [])
    print("✅ 結帳完成，內容：", cart_items)
    return redirect(url_for('thank_you'))

@app.route('/thank-you')
def thank_you():
    return render_template("thank_you.html")

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    res = supabase.table("products").select("*").eq("id", product_id).single().execute()
    product = res.data
    if not product:
        return "找不到商品", 404
    return render_template("product.html", product=product)

@app.route('/admin')
def admin():
    res = supabase.table("products").select("*").execute()
    return render_template("admin.html", products=res.data)

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
    cart = session.get('cart', [])
    for item in cart:
        if item['product_id'] == product_id:
            item['qty'] += 1
            break
    else:
        cart.append({'product_id': product_id, 'qty': 1})
    session['cart'] = cart
    print("🛒 當前購物車：", cart)
    return jsonify(success=True, count=sum(item['qty'] for item in cart))

if __name__ == '__main__':
    app.run(debug=True)
