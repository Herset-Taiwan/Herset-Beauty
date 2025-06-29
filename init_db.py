import sqlite3

# 建立一個資料庫檔案（如果已存在就不會重建）
conn = sqlite3.connect('db.sqlite')
cursor = conn.cursor()

# 建立商品資料表
cursor.execute('''
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price INTEGER,
    image TEXT,
    intro TEXT,
    feature TEXT,
    spec TEXT,
    ingredient TEXT
)
''')

conn.commit()
conn.close()
print("✅ 資料庫初始化完成！")
