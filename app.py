from flask import Flask, render_template, request, redirect
from werkzeug.utils import secure_filename
from supabase import create_client, Client
import os
import tempfile
import json

if os.environ.get("RENDER") != "true":
    from dotenv import load_dotenv
    load_dotenv()

app = Flask(__name__)
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

print("\U0001f511 SUPABASE_KEY 開頭：", SUPABASE_KEY[:30])

@app.route('/')
def index():
    res = supabase.table("products").select("*").execute()
    products = res.data
    return render_template("index.html", products=products)

@app.route('/admin')
def admin():
    res = supabase.table("products").select("*").execute()
    return render_template("admin.html", products=res.data)

@app.route('/admin/new')
def new_product():
    return render_template("new_product.html")

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    try:
        res = supabase.table("products").select("*").eq("id", product_id).single().execute()
        product = res.data
        if not product:
            return "找不到商品", 404
        return render_template("product.html", product=product)
    except Exception as e:
        print("❗️載入商品失敗：", e)
        return "載入商品時發生錯誤", 500


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

        # 多圖處理
        image_files = request.files.getlist('image_files')
        image_urls = []

        for img in image_files:
            if img and img.filename:
                filename = secure_filename(img.filename)
                storage_path = f"product_images/{filename}"
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    img.save(tmp.name)
                    try:
                        supabase.storage.from_("images").upload(storage_path, tmp.name)
                    except Exception as e:
                        print("❗️圖片上傳錯誤：", e)
                public_url = supabase.storage.from_("images").get_public_url(storage_path)
                image_urls.append(public_url)

        # 規格 options 處理（前端送成多個 options[]）
        options = [opt.strip() for opt in request.form.getlist('options[]') if opt.strip()]

        data = {
            "name": name,
            "price": price,
            "images": image_urls,
            "intro": intro,
            "feature": feature,
            "spec": spec,
            "ingredient": ingredient,
            "options": options,
            "image": image_urls[0] if image_urls else None  # ⬅️ 為了滿足原本 image 欄位 NOT NULL
        }

        print("📤 準備插入資料：", data)
        response = supabase.table("products").insert(data).execute()
        print("📥 插入結果：", response)

        if not response.data:
            print("⚠️ Supabase 寫入失敗")
            return "資料寫入失敗", 500

        return redirect('/admin')

    except Exception as e:
        print("🚨 新增商品錯誤：", e)
        return f"新增商品時發生錯誤：{str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
