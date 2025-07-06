import hashlib
import urllib.parse
import os
import random
import string
from datetime import datetime
from supabase import create_client

# ✅ Supabase 初始化（讓 utils.py 裡能直接用 supabase）
SUPABASE_URL = os.environ.get("SUPABASE_URL") or "https://bwxvuvutmexzbynzhvsd.supabase.co"
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


def generate_check_mac_value(data: dict, hash_key: str, hash_iv: str) -> str:
    sorted_items = sorted(data.items())
    raw = f"HashKey={hash_key}&" + '&'.join(f"{k}={v}" for k, v in sorted_items) + f"&HashIV={hash_iv}"
    safe = urllib.parse.quote_plus(raw).lower()
    safe = safe.replace('%21', '!').replace('%2a', '*').replace('%28', '(').replace('%29', ')').replace('%20', '+')
    return hashlib.sha256(safe.encode('utf-8')).hexdigest().upper()


def verify_check_mac_value(result: dict) -> bool:
    hash_key = '5294y06JbISpM5x9'
    hash_iv = 'v77hoKGq4kWxNNIS'

    data = {k: v for k, v in result.items() if k != "CheckMacValue"}
    expected = generate_check_mac_value(data, hash_key, hash_iv)
    return expected == result.get("CheckMacValue")


def generate_ecpay_form(order, trade_no=None):
    merchant_id = "2000132"
    hash_key = "5294y06JbISpM5x9"
    hash_iv = "v77hoKGq4kWxNNIS"
    return_url = "https://herset.co/ecpay/return"

    # ✅ 若沒傳入 trade_no，就產生新的一組，並寫入 payment_log
    if not trade_no:
        trade_no = "HS" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=18))
        supabase.table("payment_log").insert({
            "order_id": order["id"],
            "merchant_trade_no": trade_no
        }).execute()

    total = int(order["total_amount"])
    ecpay_data = {
        "MerchantID": merchant_id,
        "MerchantTradeNo": trade_no,
        "MerchantTradeDate": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
        "PaymentType": "aio",
        "TotalAmount": total,
        "TradeDesc": urllib.parse.quote_plus("HERSET 購物結帳"),
        "ItemName": "HERSET 商品組合",
        "ReturnURL": return_url,
        "ChoosePayment": "Credit",
        "ClientBackURL": "https://herset.co/thank_you"
    }

    ecpay_data["CheckMacValue"] = generate_check_mac_value(ecpay_data, hash_key, hash_iv)

    inputs = "\n".join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in ecpay_data.items()])
    return f"""
    <form id="ecpay-form" method="post" action="https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5">
        {inputs}
    </form>
    <script>document.getElementById("ecpay-form").submit();</script>
    """
