from flask import Flask, render_template, request, redirect
from werkzeug.utils import secure_filename
from supabase import create_client, Client
import os
import tempfile

app = Flask(__name__)

# ✅ Supabase 設定
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ✅ 首頁
@app.route('/')
def index():
    res = supabase.table("products").select("*").execute()
    products = res.data
    return render_template("index.html", products=products)

# ✅ 登入頁
@app.route('/login')
def login():
    return render_template("login.html")

# ✅ 購物車頁
@app.route('/cart')
def cart():
    return render_template("cart.html")

# ✅ 商品詳情
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    res = supabase.table("products").select("*").eq("id", product_id).single().execute()
    product = res.data
    if not product:
        return "找不到商品", 404
    return render_template("product.html", product=product)

# ✅ 管理頁
@app.route('/admin')
def admin():
    res = supabase.table("products").select("*").execute()
    return render_template("admin.html", products=res.data)

# ✅ 新增商品頁面
@app.route('/admin/new')
def new_product():
    return render_template("new_product.html")

# ✅ 新增商品（含圖片上傳）
@app.route('/add_product', methods=['POST'])
def add_product():
    name = request.form.get('name', '')
    price = request.form.get('price', '')
    intro = request.form.get('intro', '')
    feature = request.form.get('feature', '')
    spec = request.form.get('spec', '')
    ingredient = request.form.get('ingredient', '')
    image_url = request.form.get('image_url', '')

    image_file = request.files.get('image_file')
    image_path = image_url

    # ✅ 若有上傳檔案，則上傳至 Supabase Storage
    if image_file and getattr(image_file, 'filename', ''):
        filename = secure_filename(image_file.filename)
        storage_path = f"product_images/{filename}"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            image_file.save(tmp.name)
            supabase.storage.from_("images").upload_or_update(path=storage_path, file=tmp.name)

        # ✅ 拿到公開圖片網址
        image_path = supabase.storage.from_("images").get_public_url(storage_path)

    # ✅ 將商品資料存入 Supabase DB
    supabase.table("products").insert({
        "name": name,
        "price": price,
        "image": image_path,
        "intro": intro,
        "feature": feature,
        "spec": spec,
        "ingredient": ingredient
    }).execute()

    return redirect('/admin')

# ✅ 編輯商品
@app.route('/edit/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if request.method == 'POST':
        updated = {
            "name": request.form.get('name', ''),
            "price": request.form.get('price', ''),
            "image": request.form.get('image', ''),
            "intro": request.form.get('intro', ''),
            "feature": request.form.get('feature', ''),
            "spec": request.form.get('spec', ''),
            "ingredient": request.form.get('ingredient', '')
        }
        supabase.table("products").update(updated).eq("id", product_id).execute()
        return redirect('/admin')
    else:
        res = supabase.table("products").select("*").eq("id", product_id).single().execute()
        product = res.data
        if not product:
            return "找不到商品", 404
        return render_template("edit_product.html", product=product)

# ✅ 刪除商品
@app.route('/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    supabase.table("products").delete().eq("id", product_id).execute()
    return redirect('/admin')

# ✅ 模擬加入購物車
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_id = request.form['product_id']
    print(f"加入購物車：{product_id}")
    return redirect('/')

# ✅ 啟動伺服器
if __name__ == '__main__':
    app.run(debug=True)
