import requests
import json
import os

LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN")
print("LINE_CHANNEL_ACCESS_TOKEN exists:", bool(LINE_CHANNEL_ACCESS_TOKEN))
LINE_PUSH_API = "https://api.line.me/v2/bot/message/push"

GROUP_ID = "C240965a152796e3e6c79d2816e4d8c65"


def send_line_order_notify(order):
    text = (
        "🛒【HERSET 新訂單】\n"
        f"訂單編號：{order['order_no']}\n"
        f"收件人：{order['name']}\n"
        f"電話：{order['phone']}\n"
        f"金額：NT${order['total']}\n"
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

    r = requests.post(LINE_PUSH_API, headers=headers, data=json.dumps(payload))
    return r.status_code, r.text
