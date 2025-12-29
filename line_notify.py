import requests
import json
import os

LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN")
print("LINE_CHANNEL_ACCESS_TOKEN exists:", bool(LINE_CHANNEL_ACCESS_TOKEN))
LINE_PUSH_API = "https://api.line.me/v2/bot/message/push"

GROUP_ID = "C240965a152796e3e6c79d2816e4d8c65"


def send_line_order_notify(order, event_type="new"):
    # ===== 訊息標題依事件類型切換 =====
    if event_type == "paid":
        title = "✅【HERSET 已付款完成】"
    else:
        title = "🛒【HERSET 新訂單】"

    text = (
        f"{title}\n"
        f"訂單編號：{order.get('order_no')}\n"
        f"收件人：{order.get('name')}\n"
        f"電話：{order.get('phone')}\n"
        f"金額：NT${order.get('total')}\n"
    )

    headers = {
        "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "to": GROUP_ID,
        "messages": [{
            "type": "text",
            "text": text
        }]
    }

    r = requests.post(LINE_PUSH_API, headers=headers, json=payload, timeout=10)
    return r.status_code, r.text
