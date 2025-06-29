from flask import Flask, render_template, request, redirect
import psycopg2
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# 設定圖片上傳路徑
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ✅ PostgreSQL 連線設定
def get_db_connection():
    conn = psycopg2.connect(
        host="aws-0-ap-southeast-1.pooler.supabase.com",
        port=5432,
        database="postgres",
        user="postgres.bwxvuvutmexzbynzhvsd",
        password="Gama168.net",  # 換成你自己的 Supabase 密碼
        sslmode="require"
    )
    return conn

# ✅ 共用查詢函式
def query_fetchall(sql, params=None):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(sql, params or ())
    rows = cur.fetchall()
    columns = [desc[0] for desc in cur.description]
    results = [dict(zip(columns, row)) for row in rows]
    cur.close()
    conn.close()
    return results

def query_fetchone(sql, params=None):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(sql, params or ())
    row = cur.fetchone()
    result = None
    if row:
        columns = [desc[0] for desc in cur.description]
        result = dict(zip(columns, row))
    cur.close()
    conn.close()
    return result

# ✅ 首頁
@app.route('/')
def index():
    products = query_fetchall('SELECT id, name, price, image FROM products')
    return render_template("index.html", products=products)

# ✅ 登入
@app.route('/login')
def login():
    return render_template("login.html")

# ✅ 購物車
@app.route('/cart')
def cart():
    return render_template("cart.html")

# ✅ 商品詳情
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = query_fetchone('SELECT * FROM products WHERE id = %s', (product_id,))
    if product is None:
        return "找不到商品", 404
    return render_template("product.html", product=product)

# ✅ 商品管理
@app.route('/admin')
def admin():
    products = query_fetchall('SELECT * FROM products')
    return render_template("admin.html", products=products)

# ✅ 新增商品畫面
@app.route('/admin/new')
def new_product():
    return render_template("new_product.html")

# ✅ 新增商品處理
@app.route('/add_product', methods=['POST'])
def add_product():
    name = request.form['name']
    price = request.form['price']
    image_url = request.form.get('image_url', '')
    image_file = request.files.get('image_file')

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
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO products (name, price, image, intro, feature, spec, ingredient)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    ''', (name, price, image_path, intro, feature, spec, ingredient))
    conn.commit()
    cur.close()
    conn.close()
    return redirect('/admin')

# ✅ 編輯商品
@app.route('/edit/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if request.method == 'POST':
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            UPDATE products
            SET name=%s, price=%s, image=%s, intro=%s, feature=%s, spec=%s, ingredient=%s
            WHERE id=%s
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
        cur.close()
        conn.close()
        return redirect('/admin')
    else:
        product = query_fetchone('SELECT * FROM products WHERE id = %s', (product_id,))
        if product is None:
            return "找不到商品", 404
        return render_template("edit_product.html", product=product)

# ✅ 模擬加入購物車
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_id = request.form['product_id']
    print(f"加入購物車：{product_id}")
    return redirect('/')

# ✅ 啟動伺服器
if __name__ == '__main__':
    app.run(debug=True)
