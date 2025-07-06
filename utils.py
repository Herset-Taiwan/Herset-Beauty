import hashlib
import urllib.parse
from datetime import datetime
import urllib.parse


def generate_check_mac_value(params, hash_key, hash_iv):
    # Step 1: 排序參數（依照參數名的字母順序，大小寫有區別）
    sorted_params = sorted(params.items())
    param_str = '&'.join(f"{k}={v}" for k, v in sorted_params)

    # Step 2: 加上 HashKey 與 HashIV
    raw = f"HashKey={hash_key}&{param_str}&HashIV={hash_iv}"

    # Step 3: URL encode（小寫轉大寫，保留特殊字元）
    url_encoded = urllib.parse.quote_plus(raw).lower()

    # Step 4: 做 sha256 加密
    sha256 = hashlib.sha256()
    sha256.update(url_encoded.encode('utf-8'))
    check_mac_value = sha256.hexdigest().upper()

    return check_mac_value


def generate_check_mac_value(data: dict, hash_key: str, hash_iv: str) -> str:
    sorted_items = sorted(data.items())
    raw = f"HashKey={hash_key}&" + '&'.join(f"{k}={v}" for k, v in sorted_items) + f"&HashIV={hash_iv}"
    safe = urllib.parse.quote_plus(raw).lower()
    safe = safe.replace('%21', '!').replace('%2a', '*').replace('%28', '(').replace('%29', ')').replace('%20', '+')
    return hashlib.sha256(safe.encode('utf-8')).hexdigest().upper()

def generate_ecpay_form(order):
    merchant_id = "2000132"
    hash_key = "5294y06JbISpM5x9"
    hash_iv = "v77hoKGq4kWxNNIS"

    trade_no = order.get("merchant_trade_no") or order.get("MerchantTradeNo") or order.get("order_number") or order.get("id")
    total = int(order["total_amount"])
    return_url = "https://herset.co/ecpay/return"

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
