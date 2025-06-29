from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__)

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

# ✅ 管理頁
@app.route('/admin')
def admin():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    return render_template("admin.html", products=products)

# ✅ 表單提交新增商品
@app.route('/add_product', methods=['POST'])
def add_product():
    name = request.form['name']
    price = request.form['price']
    image = request.form['image']
    intro = request.form['intro']
    feature = request.form['feature']
    spec = request.form['spec']
    ingredient = request.form['ingredient']

    conn = get_db_connection()
    conn.execute('''
        INSERT INTO products (name, price, image, intro, feature, spec, ingredient)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (name, price, image, intro, feature, spec, ingredient))
    conn.commit()
    conn.close()

    return redirect('/admin')

if __name__ == '__main__':
    app.run(debug=True)
