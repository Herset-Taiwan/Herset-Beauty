from flask import Flask, render_template, request, redirect
from werkzeug.utils import secure_filename
from supabase import create_client, Client
import os
import tempfile
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.route('/')
def index():
    res = supabase.table("products").select("*").execute()
    products = res.data
    return render_template("index.html", products=products)

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/cart')
def cart():
    return render_template("cart.html")

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

        # 處理圖片
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

        # 商品規格
        options = request.form.getlist('options[]')

        # 為了支援原本 image 欄位（非空限制），保留第一張圖片為主圖
        cover_image = image_urls[0] if image_urls else ""

        # 整理資料
        data = {
            "name": name,
            "price": price,
            "image": cover_image,
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
            "price": request.form['price'],
            "image": request.form['image'],
            "intro": request.form['intro'],
            "feature": request.form['feature'],
            "spec": request.form['spec'],
            "ingredient": request.form['ingredient'],
            "category": request.form.get('category', '')
        }
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
    product_id = request.form['product_id']
    print(f"加入購物車：{product_id}")
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
