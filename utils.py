import hashlib
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
