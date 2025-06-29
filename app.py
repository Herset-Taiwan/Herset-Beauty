from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/cart')
def cart():
    return render_template("cart.html")

@app.route('/product/<product_id>')
def product_detail(product_id):
    return render_template("product.html")


if __name__ == '__main__':
    app.run(debug=True)
