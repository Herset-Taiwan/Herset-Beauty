from flask import Flask, render_template, request, redirect
import sqlite3
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# 設定圖片上傳路徑
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_db_connection():
    conn = sqlite3.connect('db.sqlite')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    products = conn.execute('SELECT id, name, price, image FROM products').fetchall()
    conn.close()
    return render_template("index.html", products=products)

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/cart')
def cart():
    return render_template("cart.html")

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    conn.close()
    if product is None:
        return "找不到商品", 404
    return render_template("product.html", product=product)

# ✅ 商品管理頁
@app.route('/admin')
def admin():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    return render_template("admin.html", products=products)

# ✅ 顯示新增商品頁
@app.route('/admin/new')
def new_product():
    return render_template("new_product.html")

# ✅ 新增商品（圖片網址或上傳圖片）
@app.route('/add_product', methods=['POST'])
def add_product():
    name = request.form['name']
    price = request.form['price']
    image_url = request.form.get('image_url', '')
    image_file = request.files.get('image_file')

    # 儲存圖片檔案（若有）
    image_path = image_url
    if image_file and image_file.filename:
        filename = secure_filename(image_file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(save_path)
        image_path = '/' + save_path.replace('\\', '/')

    intro = request.form['intro']
    feature = request.form['feature']
    spec = request.form['spec']
    ingredient = request.form['ingredient']

    conn = get_db_connection()
    conn.execute('''
        INSERT INTO products (name, price, image, intro, feature, spec, ingredient)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (name, price, image_path, intro, feature, spec, ingredient))
    conn.commit()
    conn.close()
    return redirect('/admin')

# ✅ 編輯商品
@app.route('/edit/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    conn = get_db_connection()

    if request.method == 'POST':
        conn.execute('''
            UPDATE products
            SET name=?, price=?, image=?, intro=?, feature=?, spec=?, ingredient=?
            WHERE id=?
        ''', (
            request.form['name'],
            request.form['price'],
            request.form['image'],
            request.form['intro'],
            request.form['feature'],
            request.form['spec'],
            request.form['ingredient'],
            product_id
        ))
        conn.commit()
        conn.close()
        return redirect('/admin')
    
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_id = request.form['product_id']
    # 暫時模擬加入購物車，之後可擴充 session 或 DB
    print(f"加入購物車：{product_id}")
    return redirect('/')

    product = conn.execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
    conn.close()
    if product is None:
        return "找不到商品", 404
    return render_template("edit_product.html", product=product)

if __name__ == '__main__':
    app.run(debug=True)
