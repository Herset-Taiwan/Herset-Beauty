from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')  # 請確認 templates/index.html 存在

# 不要加 app.run()，Render 會自動使用 gunicorn 啟動這個 app
