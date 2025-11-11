# -*- coding: utf-8 -*-
import hashlib
import urllib.parse
import os
import random
import string
from datetime import datetime
from supabase import create_client

# ==============================
# Supabase 初始化（保留你原本行為）
# ==============================
SUPABASE_URL = os.environ.get("SUPABASE_URL") or "https://bwxvuvutmexzbynzhvsd.supabase.co"
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ==============================
# ECPay 設定：環境變數切換
# ==============================
ECPAY_ENV = (os.environ.get("ECPAY_ENV") or "stage").lower()  # 'stage' | 'prod'
IS_SANDBOX = (ECPAY_ENV != "prod")

# 正式／測試 API 端點
ECPAY_CASHIER_URL = (
    "https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5"
    if IS_SANDBOX else
    "https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5"
)

# 金鑰與商店參數（用環境變數；若沒設且你在 sandbox，就用綠界公開測試值）
MERCHANT_ID = os.environ.get("ECPAY_MERCHANT_ID") or ("2000132" if IS_SANDBOX else None)
HASH_KEY    = os.environ.get("ECPAY_HASH_KEY")    or ("5294y06JbISpM5x9" if IS_SANDBOX else None)
HASH_IV     = os.environ.get("ECPAY_HASH_IV")     or ("v77hoKGq4kWxNNIS" if IS_SANDBOX else None)

# 回傳網址（後端接收通知）
RETURN_URL       = os.environ.get("ECPAY_RETURN_URL")       or "https://herset.co/ecpay/return"
CLIENT_BACK_URL  = os.environ.get("ECPAY_CLIENT_BACK_URL")  or "https://herset.co/thank_you"

def _assert_ecpay_config():
    """在正式環境保證必要參數存在。"""
    if not MERCHANT_ID or not HASH_KEY or not HASH_IV:
        raise RuntimeError("ECPay 參數未設定完整：請設定 ECPAY_MERCHANT_ID / ECPAY_HASH_KEY / ECPAY_HASH_IV")

# ==============================
# 簽章工具
# ==============================
def generate_check_mac_value(data: dict, hash_key: str, hash_iv: str) -> str:
    # 依鍵名升冪排序
    sorted_items = sorted(data.items())
    # 按照綠界規則組字串
    raw = f"HashKey={hash_key}&" + "&".join(f"{k}={v}" for k, v in sorted_items) + f"&HashIV={hash_iv}"
    # URL encode（+ 例外字符處理）→ 小寫 → SHA256 → 大寫
    safe = urllib.parse.quote_plus(raw).lower()
    safe = (
        safe.replace('%21', '!')
            .replace('%2a', '*')
            .replace('%28', '(')
            .replace('%29', ')')
            .replace('%20', '+')
    )
    return hashlib.sha256(safe.encode('utf-8')).hexdigest().upper()

def verify_check_mac_value(result: dict) -> bool:
    """驗證綠界回傳的 CheckMacValue。"""
    _assert_ecpay_config()
    data = {k: v for k, v in result.items() if k != "CheckMacValue"}
    expected = generate_check_mac_value(data, HASH_KEY, HASH_IV)
    return expected == result.get("CheckMacValue")

# ==============================
# 表單產生（信用卡）
# ==============================
def _new_trade_no(prefix: str = "HS") -> str:
    # 依綠界規範長度 <= 20，這裡 prefix(2) + 18 隨機 = 20
    return prefix + ''.join(random.choices(string.ascii_uppercase + string.digits, k=18))

def generate_ecpay_form(order: dict, trade_no: str = None):
    """
    回傳 (trade_no, auto_post_html)
    - 會在新交易時寫入 payment_log（僅含 order_id / merchant_trade_no）
    - 依 ECPAY_ENV 自動切換 stage/prod 端點與金鑰
    """
    _assert_ecpay_config()

    # 交易編號
    is_new = False
    if not trade_no:
        is_new = True
        trade_no = _new_trade_no()

    # 新交易寫入 payment_log（對應你既有流程）
    if is_new:
        supabase.table("payment_log").insert({
            "order_id": order["id"],
            "merchant_trade_no": trade_no
        }).execute()

    total = int(order["total_amount"])

    payload = {
        "MerchantID": MERCHANT_ID,
        "MerchantTradeNo": trade_no,
        "MerchantTradeDate": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
        "PaymentType": "aio",
        "TotalAmount": total,
        "TradeDesc": urllib.parse.quote_plus("HERSET 購物結帳"),
        "ItemName": "HERSET 商品組合",
        "ReturnURL": RETURN_URL,
        "ChoosePayment": "Credit",
        "ClientBackURL": CLIENT_BACK_URL
    }

    payload["CheckMacValue"] = generate_check_mac_value(payload, HASH_KEY, HASH_IV)

    inputs = "\n".join(
        f'<input type="hidden" name="{k}" value="{v}">' for k, v in payload.items()
    )
    form_html = f"""
<form id="ecpay-form" method="post" action="{ECPAY_CASHIER_URL}">
{inputs}
</form>
<script>document.getElementById("ecpay-form").submit();</script>
""".strip()

    return trade_no, form_html
