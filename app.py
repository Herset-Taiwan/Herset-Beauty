from flask import Flask, render_template, request, redirect
from werkzeug.utils import secure_filename
from supabase import create_client, Client
import os
import tempfile

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
    name = request.form['name']
    price = request.form['price']
    image_file = request.files.get('image_file')
    image_url = request.form.get('image_url', '')

    image_path = image_url

    if image_file and image_file.filename:
        filename = secure_filename(image_file.filename)
        storage_path = f"product_images/{filename}"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            image_file.save(tmp.name)

            try:
                supabase.storage.from_("images").update(path=storage_path, file=tmp.name)

            except Exception as e:
                # 若已存在可跳過或使用 overwrite 覆蓋
                print("❗️圖片上傳錯誤：", e)

        image_path = supabase.storage.from_("images").get_public_url(storage_path)

    intro = request.form['intro']
    feature = request.form['feature']
    spec = request.form['spec']
    ingredient = request.form['ingredient']

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
            "ingredient": request.form['ingredient']
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
