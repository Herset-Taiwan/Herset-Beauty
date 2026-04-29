import json
import os
import re
import io
import random
import uuid
import unicodedata
from PIL import Image, ImageOps
from datetime import datetime
from flask import render_template, request, jsonify, session, redirect, flash


def register_landing_module(app, supabase, TW, generate_merchant_trade_no):
    # ======================================================
    # Helpers
    # ======================================================
    
    def safe_filename(name):
        name = os.path.basename(name or "").strip()
        if not name:
            return "image"

        normalized = unicodedata.normalize("NFKD", name)
        ascii_name = normalized.encode("ascii", "ignore").decode("ascii")

        if "." in ascii_name:
            base, ext = ascii_name.rsplit(".", 1)
            ext = "." + ext.lower()
        else:
            base, ext = ascii_name, ".jpg"

        base = base.lower().strip()
        base = re.sub(r"[^a-z0-9._-]+", "_", base)
        base = re.sub(r"_+", "_", base)
        base = base.strip("._-")

        if not base:
            base = "image"

        return base + ext

    def crop_and_resize_image(file_bytes, target_width, target_height, quality=88):
        img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
        img = ImageOps.exif_transpose(img)
        img = ImageOps.fit(
            img,
            (target_width, target_height),
            method=Image.Resampling.LANCZOS,
            centering=(0.5, 0.5)
        )

        output = io.BytesIO()
        img.save(output, format="JPEG", quality=quality, optimize=True)
        output.seek(0)
        return output.read()
    
    def resize_image_keep_ratio(file_bytes, max_width=1200, quality=88):
        img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
        img = ImageOps.exif_transpose(img)

        if img.width > max_width:
            ratio = max_width / float(img.width)
            new_height = int(img.height * ratio)
            img = img.resize((max_width, new_height), Image.Resampling.LANCZOS)

        output = io.BytesIO()
        img.save(output, format="JPEG", quality=quality, optimize=True)
        output.seek(0)
        return output.read()


    def upload_bytes_to_supabase(file_bytes, original_name, folder="landing"):
        safe_name = safe_filename(original_name)
        base_name = safe_name.rsplit(".", 1)[0]

        filename = "{0}/{1}_{2}.jpg".format(
            folder,
            datetime.now(TW).strftime("%Y%m%d%H%M%S"),
            base_name + "_" + uuid.uuid4().hex[:6]
        )

        try:
            res = supabase.storage.from_("images").upload(
                filename,
                file_bytes,
                {"content-type": "image/jpeg"}
            )

            if hasattr(res, "error") and res.error:
                print("UPLOAD ERROR:", res.error)
                return None

            return supabase.storage.from_("images").get_public_url(filename)

        except Exception as e:
            print("UPLOAD ERROR:", str(e))
            return None


    def build_hero_images(file):
        if not file or file.filename == "":
            return None, None

        raw = file.read()
        if not raw:
            return None, None

        desktop = crop_and_resize_image(raw, 1920, 900)
        mobile = crop_and_resize_image(raw, 900, 1200)

        desktop_url = upload_bytes_to_supabase(desktop, "desktop_" + file.filename)
        mobile_url = upload_bytes_to_supabase(mobile, "mobile_" + file.filename)

        return desktop_url, mobile_url


    def upload_secondary_images(files):
        urls = []

        for f in files:
            if not f or not f.filename:
                continue

            try:
                raw = f.read()
                if not raw:
                    continue

                img = crop_and_resize_image(raw, 1200, 1200)
                url = upload_bytes_to_supabase(
                    img,
                    "secondary_" + f.filename,
                    folder="landing/secondary"
                )

                if url:
                    urls.append(url)

            except Exception as e:
                print("SECONDARY ERROR:", str(e))

        return urls
    
    def upload_middle_images(files):
        urls = []

        for f in files:
            if not f or not f.filename:
                continue

            try:
                raw = f.read()
                if not raw:
                    continue

                img = resize_image_keep_ratio(raw, max_width=1200)
                url = upload_bytes_to_supabase(
                    img,
                    "middle_" + f.filename,
                    folder="landing/middle"
                )

                if url:
                    urls.append(url)

            except Exception as e:
                print("MIDDLE IMAGE ERROR:", str(e))
    
        return urls

    def upload_offer_images(files):
        urls = []

        for f in files:
            if not f or not f.filename:
                urls.append("")
                continue

            try:
                raw = f.read()
                if not raw:
                    urls.append("")
                    continue

                img = crop_and_resize_image(raw, 800, 600)
                url = upload_bytes_to_supabase(
                    img,
                    "offer_" + f.filename,
                    folder="landing/offers"
                )

                urls.append(url or "")

            except Exception as e:
                print("OFFER IMAGE ERROR:", str(e))
                urls.append("")

        return urls   
    
    def safe_json_loads(value, default):
        if value is None or value == "":
            return default
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except Exception:
            return default

    def slugify(text):
        text = (text or "").strip().lower()
        text = re.sub(r'[^a-z0-9\u4e00-\u9fff\-_\s]+', '', text)
        text = re.sub(r'[\s_]+', '-', text)
        text = re.sub(r'-{2,}', '-', text)
        return text.strip('-')

    def get_landing_page_by_slug(slug):
        res = (
            supabase.table("landing_pages")
            .select("*")
            .eq("slug", slug)
            .eq("is_active", True)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        return rows[0] if rows else None

    def get_landing_page_by_id(page_id):
        res = (
            supabase.table("landing_pages")
            .select("*")
            .eq("id", page_id)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        return rows[0] if rows else None

    def get_landing_offers(page_id, active_only=False):
        q = (
            supabase.table("landing_page_offers")
            .select("*")
            .eq("landing_page_id", page_id)
            .order("sort_order")
        )
        if active_only:
            q = q.eq("is_active", True)
        res = q.execute()
        return res.data or []

    def get_landing_offer_by_id(offer_id):
        res = (
            supabase.table("landing_page_offers")
            .select("*")
            .eq("id", offer_id)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        return rows[0] if rows else None

    def parse_landing_page_form(form):
        faq_list = []
        faq_qs = form.getlist("faq_q[]")
        faq_as = form.getlist("faq_a[]")

        for i in range(max(len(faq_qs), len(faq_as))):
            q = (faq_qs[i] if i < len(faq_qs) else "").strip()
            a = (faq_as[i] if i < len(faq_as) else "").strip()
            if q or a:
                faq_list.append({"q": q, "a": a})

        sections_json = {
            "show_features": form.get("show_features") == "1",
            "show_reviews": form.get("show_reviews") == "1",
            "show_faq": form.get("show_faq") == "1",
            "show_buy_box": form.get("show_buy_box") != "0",
        }

        theme_json = {
            "primary_color": (form.get("primary_color") or "").strip(),
            "secondary_color": (form.get("secondary_color") or "").strip(),
            "accent_color": (form.get("accent_color") or "").strip(),
        }

        slug = slugify(form.get("slug") or form.get("name") or "")
        secondary_urls = [x.strip() for x in form.getlist("secondary_images[]") if x.strip()]
        # ⭐ 新增：解析中間圖片
        middle_images = [x.strip() for x in form.getlist("middle_images[]") if x.strip()]

        return {
            "name": (form.get("name") or "").strip(),
            "slug": slug,
            "title": (form.get("title") or "").strip(),
            "subtitle": (form.get("subtitle") or "").strip(),
            "hero_image": (form.get("hero_image") or "").strip(),
            "hero_image_mobile": (form.get("hero_image_mobile") or "").strip(),
            "description": (form.get("description") or "").strip(),
            "cta_text": (form.get("cta_text") or "立即下單").strip(),
            "cta_anchor": (form.get("cta_anchor") or "#buy").strip(),
            "buy_title": (form.get("buy_title") or "").strip(),
            "affiliate_code": (form.get("affiliate_code") or "").strip(),
            "faq_json": faq_list,
            "sections_json": sections_json,
            "theme_json": theme_json,
            "is_active": form.get("is_active") == "1",
            "updated_at": datetime.now(TW).isoformat(),
            "secondary_images_json": secondary_urls,
            
            "content_images_json": {
                "after_buy": middle_images
            },
            "slider_interval": int(form.get("slider_interval") or 3000) if str(form.get("slider_interval") or "").isdigit() else 3000,
        }

    def parse_landing_offers_form(form, landing_page_id):
        offers = []

        offer_names = form.getlist("offer_name[]")
        offer_subtitles = form.getlist("offer_subtitle[]")
        offer_badges = form.getlist("offer_badge[]")
        offer_prices = form.getlist("offer_price[]")
        offer_compare_prices = form.getlist("offer_compare_at_price[]")
        offer_product_ids = form.getlist("offer_product_id[]")
        offer_bundle_ids = form.getlist("offer_bundle_id[]")
        offer_image_urls = form.getlist("offer_image_url[]")
        offer_defaults = form.getlist("offer_is_default[]")
        offer_actives = form.getlist("offer_is_active[]")

        total_rows = len(offer_names)

        for i in range(total_rows):
            name = (offer_names[i] or "").strip()
            if not name:
                continue

            product_id = (offer_product_ids[i] if i < len(offer_product_ids) else "").strip()
            bundle_id_raw = (offer_bundle_ids[i] if i < len(offer_bundle_ids) else "").strip()

            try:
                price = float((offer_prices[i] if i < len(offer_prices) else "0") or 0)
            except Exception:
                price = 0

            try:
                compare_at_price = float((offer_compare_prices[i] if i < len(offer_compare_prices) else "0") or 0)
            except Exception:
                compare_at_price = 0

            offer = {
                "landing_page_id": landing_page_id,
                "offer_name": name,
                "subtitle": (offer_subtitles[i] if i < len(offer_subtitles) else "").strip(),
                "badge": (offer_badges[i] if i < len(offer_badges) else "").strip(),
                "price": price,
                "compare_at_price": compare_at_price if compare_at_price > 0 else None,
                "product_id": product_id or None,
                "bundle_id": int(bundle_id_raw) if bundle_id_raw.isdigit() else None,
                
                "image_url": (offer_image_urls[i] if i < len(offer_image_urls) else "").strip() or None,
                "products_json": [],
                "is_default": str(i) in offer_defaults,
                "is_active": str(i) in offer_actives,
                "sort_order": i
            }

            if offer["bundle_id"]:
                offer["product_type"] = "bundle"
            elif offer["product_id"]:
                offer["product_type"] = "single"
            else:
                offer["product_type"] = "custom"

            offers.append(offer)

        return offers
    
    # ======================================================
    # 前台：Landing Page
    # ======================================================
    @app.route("/landing/<slug>")
    def landing_page(slug):
        page = get_landing_page_by_slug(slug)
        if not page:
            return "找不到頁面", 404

        offers = get_landing_offers(page["id"], active_only=True)

        product_map = {}
        bundle_map = {}

        product_ids = [o["product_id"] for o in offers if o.get("product_id")]
        bundle_ids = [o["bundle_id"] for o in offers if o.get("bundle_id")]

        if product_ids:
            rows = (
                supabase.table("products")
                .select("id,name,price,discount_price,images")
                .in_("id", product_ids)
                .execute()
                .data or []
            )
            product_map = {str(r["id"]): r for r in rows}

        if bundle_ids:
            rows = (
                supabase.table("bundles")
                .select("id,price,compare_at,shell_product_id")
                .in_("id", bundle_ids)
                .execute()
                .data or []
            )
            bundle_map = {r["id"]: r for r in rows}

        for o in offers:
            if o.get("product_id"):
                p = product_map.get(str(o["product_id"])) or {}
                o["source_name"] = p.get("name", "")
            elif o.get("bundle_id"):
                o["source_name"] = "套組"

        page["faq_json"] = safe_json_loads(page.get("faq_json"), [])
        page["sections_json"] = safe_json_loads(page.get("sections_json"), {})
        page["theme_json"] = safe_json_loads(page.get("theme_json"), {})
        page["content_images_json"] = safe_json_loads(page.get("content_images_json"), {})

        return render_template("landing_page.html", page=page, offers=offers)

    @app.route("/api/landing-order", methods=["POST"])
    def api_landing_order():
        data = request.get_json(silent=True) or request.form

        slug = (data.get("slug") or "").strip()
        offer_id_raw = str(data.get("offer_id") or "").strip()
        qty_raw = str(data.get("qty") or "1").strip()

        receiver_name = (data.get("name") or "").strip()
        receiver_phone = (data.get("phone") or "").strip()
        guest_email = (data.get("email") or "").strip()
        intended_payment_method = (data.get("payment_method") or "").strip().lower()

        shipping_method = (
            data.get("shipping_method")
            or data.get("delivery_method")
            or data.get("shipping")
            or "home"
        ).strip().lower()

        store_type = (
            data.get("store_type")
            or data.get("cvs_type")
            or data.get("store_brand")
            or ""
        ).strip().lower()

        store_name = (
            data.get("store_name")
            or data.get("cvs_store_name")
            or data.get("store_no")
            or data.get("store_id")
            or ""
        ).strip()

        store_address = (
            data.get("store_address")
            or data.get("cvs_store_address")
            or ""
        ).strip()

        home_address = (
            data.get("receiver_address")
            or data.get("shipping_address")
            or data.get("home_address")
            or data.get("delivery_address")
            or ""
        ).strip()

        # 兼容你目前前端如果還是只送 address：
        # 只有宅配才把 address 當宅配地址使用，避免超商時誤吃會員舊地址 test4。
        legacy_address = (data.get("address") or "").strip()

        if shipping_method in ("store", "cvs", "711", "family", "超商", "超商取貨"):
            shipping_method = "store"
        else:
            shipping_method = "home"

        receiver_address = ""

        if shipping_method not in ("home", "store"):
            shipping_method = "home"

        if not slug:
            return jsonify({"ok": False, "error": "缺少頁面 slug"}), 400

        if not offer_id_raw.isdigit():
            return jsonify({"ok": False, "error": "方案錯誤"}), 400

        if not receiver_name or not receiver_phone:
            return jsonify({"ok": False, "error": "請填寫收件人姓名與手機"}), 400

        if shipping_method == "home":
            receiver_address = home_address or legacy_address

            if not receiver_address:
                return jsonify({"ok": False, "error": "請填寫宅配地址"}), 400

        else:
            if store_type in ("7-11", "711", "seven", "seven_eleven"):
                store_type = "711"
            elif store_type in ("family", "familymart", "全家"):
                store_type = "family"

            if store_type not in ("711", "family"):
                return jsonify({"ok": False, "error": "請選擇超商類型"}), 400

            if not store_name and not store_address:
                return jsonify({"ok": False, "error": "請填寫門市名稱或店號"}), 400

            store_type_text = "7-11" if store_type == "711" else "全家"

            receiver_address = " / ".join([
                x for x in [
                    "{} 超商取貨".format(store_type_text),
                    store_name,
                    store_address
                ]
                if x
            ])

        try:
            qty = max(1, int(qty_raw))
        except Exception:
            qty = 1

        page = get_landing_page_by_slug(slug)
        if not page:
            return jsonify({"ok": False, "error": "找不到一頁式頁面"}), 404

        offer = get_landing_offer_by_id(int(offer_id_raw))
        if not offer or int(offer.get("landing_page_id") or 0) != int(page["id"]):
            return jsonify({"ok": False, "error": "找不到方案"}), 404

        try:
            unit_price = int(round(float(offer.get("price") or 0)))
        except Exception:
            unit_price = 0

        if unit_price <= 0:
            return jsonify({"ok": False, "error": "方案價格異常"}), 400

        subtotal = unit_price * qty
        shipping_fee = 0
        discount_amount = 0
        final_total = max(subtotal + shipping_fee - discount_amount, 0)

        merchant_trade_no = generate_merchant_trade_no()
        order_no = "LPG-" + datetime.now(TW).strftime("%Y%m%d%H%M%S") + str(random.randint(100, 999))

        member_id = session.get("member_id")

        order_data = {
            "member_id": member_id,
            "guest_name": None if member_id else receiver_name,
            "guest_phone": None if member_id else receiver_phone,
            "guest_email": None if member_id else guest_email,
            "guest_address": None if member_id else receiver_address,
            "receiver_name": receiver_name,
            "receiver_phone": receiver_phone,
            "receiver_address": receiver_address,
            "shipping_method": shipping_method,
            "store_type": store_type if shipping_method == "store" else None,
            "store_name": store_name if shipping_method == "store" else None,
            "landing_page_id": page["id"],
            "landing_offer_id": offer["id"],
            "total_amount": final_total,
            "status": "pending",
            "MerchantTradeNo": merchant_trade_no,
            "payment_status": "unpaid",
            "payment_method": None,
            "shipping_fee": shipping_fee,
            "discount_amount": discount_amount,
            "amount_payable_cents": final_total * 100,
            "currency": "TWD",
            "order_no": order_no,
            "intended_payment_method": intended_payment_method or None,
            "affiliate_code": page.get("affiliate_code") or session.get("affiliate_ref"),
            "created_at": datetime.now(TW).isoformat()
        }

        order_res = supabase.table("orders").insert(order_data).execute()
        order_rows = order_res.data or []
        if not order_rows:
            return jsonify({"ok": False, "error": "建立訂單失敗"}), 500

        order = order_rows[0]
        order_id = order["id"]

        item_data = {
            "order_id": order_id,
            "product_id": str(offer.get("product_id") or ""),
            "product_name": offer.get("offer_name") or "Landing Offer",
            "qty": qty,
            "price": unit_price,
            "subtotal": final_total,
            "option": offer.get("offer_name") or ""
        }
        supabase.table("order_items").insert(item_data).execute()

        session["current_trade_no"] = merchant_trade_no
        session["pending_order_id"] = order_id

        return jsonify({
            "ok": True,
            "order_id": order_id,
            "redirect_url": "/choose-payment?order_id={}".format(order_id)
        })
    def get_affiliate_by_code(code):
        code = (code or "").strip()
        if not code:
            return None

        try:
            rows = (
                supabase.table("affiliates")
                .select("*")
                .eq("code", code)
                .eq("is_active", True)
                .limit(1)
                .execute()
                .data or []
            )
            return rows[0] if rows else None
        except Exception as e:
            print("[affiliate report] load affiliate failed:", e)
            return None


    def build_affiliate_landing_report_rows(affiliate_code):
        from dateutil import parser

        affiliate_code = (affiliate_code or "").strip()

        try:
            aff = get_affiliate_by_code(affiliate_code)
        except Exception:
            aff = None

        if not aff:
            return {
                "affiliate": None,
                "rows": [],
                "grand_order_count": 0,
                "grand_sales_total": 0,
                "grand_commission_total": 0
            }

        commission_rate = float(aff.get("commission_rate") or 0)

        try:
            pages = (
                supabase.table("landing_pages")
                .select("id,name,slug,title,affiliate_code")
                .eq("affiliate_code", affiliate_code)
                .execute()
                .data or []
            )
        except Exception as e:
            print("[affiliate public report] load pages failed:", e)
            pages = []

        page_map = {int(p["id"]): p for p in pages if p.get("id") is not None}

        try:
            orders = (
                supabase.table("orders")
                .select("*")
                .eq("affiliate_code", affiliate_code)
                .eq("payment_status", "paid")
                .neq("status", "cancelled")
                .order("created_at", desc=True)
                .execute()
                .data or []
            )
        except Exception as e:
            print("[affiliate public report] load orders failed:", e)
            orders = []

        orders = [o for o in orders if o.get("landing_page_id")]

        offer_ids = list({
            o.get("landing_offer_id")
            for o in orders
            if o.get("landing_offer_id")
        })

        offer_map = {}
        if offer_ids:
            try:
                offer_rows = (
                    supabase.table("landing_page_offers")
                    .select("id,offer_name")
                    .in_("id", offer_ids)
                    .execute()
                    .data or []
                )
                offer_map = {
                    int(x["id"]): x
                    for x in offer_rows
                    if x.get("id") is not None
                }
            except Exception as e:
                print("[affiliate public report] load offers failed:", e)

        def format_tw_datetime(val):
            if not val:
                return "—"
            try:
                dt = parser.parse(str(val))
                return dt.astimezone(TW).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return str(val)

        rows = []
        grand_order_count = 0
        grand_sales_total = 0
        grand_commission_total = 0

        for o in orders:
            landing_page_id = int(o.get("landing_page_id") or 0)
            page = page_map.get(landing_page_id) or {}
            offer = offer_map.get(int(o.get("landing_offer_id") or 0)) or {}

            total_amount = int(o.get("total_amount") or 0)

            stored_commission = o.get("commission_amount")
            if stored_commission is None or int(stored_commission or 0) <= 0:
                commission_amount = int(total_amount * commission_rate / 100)
            else:
                commission_amount = int(stored_commission or 0)

            grand_order_count += 1
            grand_sales_total += total_amount
            grand_commission_total += commission_amount

            rows.append({
                "paid_at": format_tw_datetime(o.get("paid_at") or o.get("created_at")),
                "order_no": o.get("order_no") or o.get("MerchantTradeNo") or o.get("id"),
                "landing_page_name": page.get("name") or page.get("title") or "一頁式頁面",
                "landing_page_slug": page.get("slug") or "",
                "offer_name": offer.get("offer_name") or "—",
                "receiver_name": o.get("receiver_name") or o.get("guest_name") or "—",
                "total_amount": total_amount,
                "commission_amount": commission_amount
            })

        return {
            "affiliate": aff,
            "rows": rows,
            "grand_order_count": grand_order_count,
            "grand_sales_total": grand_sales_total,
            "grand_commission_total": grand_commission_total
        }


    @app.route("/affiliate-report/<code>", methods=["GET", "POST"])
    def affiliate_public_report(code):
        import hashlib

        code = (code or "").strip()
        affiliate = get_affiliate_by_code(code)

        if not affiliate:
            return "找不到團購主或此團購主未啟用", 404

        session_key = "affiliate_report_auth_{}".format(code)
        error = ""

        if request.method == "POST":
            password = (request.form.get("password") or "").strip()
            password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

            saved_hash = (affiliate.get("report_password_hash") or "").strip()

            if saved_hash and password_hash == saved_hash:
                session[session_key] = True
                return redirect("/affiliate-report/{}".format(code))

            error = "密碼錯誤，請重新輸入"

        if not session.get(session_key):
            return render_template(
                "affiliate_report_login.html",
                affiliate=affiliate,
                code=code,
                error=error
            )

        report = build_affiliate_landing_report_rows(code)

        return render_template(
            "affiliate_public_report.html",
            affiliate=affiliate,
            rows=report["rows"],
            grand_order_count=report["grand_order_count"],
            grand_sales_total=report["grand_sales_total"],
            grand_commission_total=report["grand_commission_total"]
        )


    @app.route("/affiliate-report/<code>/logout")
    def affiliate_public_report_logout(code):
        code = (code or "").strip()
        session.pop("affiliate_report_auth_{}".format(code), None)
        return redirect("/affiliate-report/{}".format(code))
    @app.route("/admin0363/landing-pages/report")
    def admin_landing_pages_report():
        if not session.get("admin_logged_in"):
            return redirect("/admin0363")

        from dateutil import parser

        def format_tw_datetime(val):
            if not val:
                return "—"
            try:
                dt = parser.parse(str(val))
                return dt.astimezone(TW).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return str(val)

        def format_payment_method(order_row):
            method = (
                (order_row.get("payment_method") or "").strip().lower()
                or (order_row.get("intended_payment_method") or "").strip().lower()
            )

            if method in ("transfer", "bank", "bank_transfer", "atm"):
                return "轉帳付款"
            if method in ("linepay", "line_pay", "line"):
                return "LINE Pay"
            if method in ("ecpay", "credit", "credit_card"):
                return "信用卡"
            if method:
                return method

            return "—"

        page_id_raw = (request.args.get("page_id") or "").strip()
        affiliate_code_raw = (request.args.get("affiliate_code") or "").strip()
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()

        # ===== 1. 讀取一頁式頁面 =====
        try:
            pages = (
                supabase.table("landing_pages")
                .select("id,name,slug,title,affiliate_code")
                .order("created_at", desc=True)
                .execute()
                .data or []
            )
        except Exception as e:
            print("[landing report] load pages failed:", e)
            pages = []

        page_map = {int(p["id"]): p for p in pages if p.get("id") is not None}

        # ===== 2. 讀取團購主 =====
        try:
            affiliates = (
                supabase.table("affiliates")
                .select("name,code,commission_rate,is_active")
                .order("created_at", desc=True)
                .execute()
                .data or []
            )
        except Exception as e:
            print("[landing report] load affiliates failed:", e)
            affiliates = []

        affiliate_map = {
            str(a.get("code") or ""): a
            for a in affiliates
            if a.get("code")
        }

        # ===== 3. 讀取一頁式訂單 =====
        try:
            order_q = (
                supabase.table("orders")
                .select("*")
                .eq("payment_status", "paid")
                .neq("status", "cancelled")
                .not_.is_("landing_page_id", "null")
                .order("created_at", desc=True)
            )

            if page_id_raw.isdigit():
                order_q = order_q.eq("landing_page_id", int(page_id_raw))

            if affiliate_code_raw:
                order_q = order_q.eq("affiliate_code", affiliate_code_raw)

            orders = order_q.execute().data or []

        except Exception as e:
            print("[landing report] load orders failed:", e)
            orders = []

        # ===== 4. 日期過濾 =====
        filtered_orders = []

        for o in orders:
            filter_date = str(o.get("paid_at") or o.get("created_at") or "")

            if date_from and filter_date[:10] < date_from:
                continue

            if date_to and filter_date[:10] > date_to:
                continue

            filtered_orders.append(o)

        # ===== 5. 補方案名稱 =====
        offer_ids = list({
            o.get("landing_offer_id")
            for o in filtered_orders
            if o.get("landing_offer_id")
        })

        offer_map = {}

        if offer_ids:
            try:
                offer_rows = (
                    supabase.table("landing_page_offers")
                    .select("id,offer_name")
                    .in_("id", offer_ids)
                    .execute()
                    .data or []
                )
                offer_map = {
                    int(x["id"]): x
                    for x in offer_rows
                    if x.get("id") is not None
                }
            except Exception as e:
                print("[landing report] load offers failed:", e)
                offer_map = {}

        # ===== 6. 統計 =====
        summary_map = {}

        for o in filtered_orders:
            landing_page_id = o.get("landing_page_id")
            try:
                landing_page_id_int = int(landing_page_id)
            except Exception:
                landing_page_id_int = 0

            page = page_map.get(landing_page_id_int) or {}
            page_name = page.get("name") or page.get("title") or "未命名一頁式"
            page_slug = page.get("slug") or ""

            affiliate_code = str(o.get("affiliate_code") or page.get("affiliate_code") or "").strip()
            affiliate = affiliate_map.get(affiliate_code) or {}

            commission_rate = float(affiliate.get("commission_rate") or 0)
            total_amount = int(o.get("total_amount") or 0)

            # 舊訂單如果 commission_amount 沒存，就用團購主比例即時計算
            stored_commission = o.get("commission_amount")
            if stored_commission is None or int(stored_commission or 0) <= 0:
                commission_amount = int(total_amount * commission_rate / 100)
            else:
                commission_amount = int(stored_commission or 0)

            key = "{}|{}".format(landing_page_id_int, affiliate_code)

            row = summary_map.setdefault(key, {
                "landing_page_id": landing_page_id_int,
                "landing_page_name": page_name,
                "landing_page_slug": page_slug,
                "affiliate_code": affiliate_code or "未綁定",
                "affiliate_name": affiliate.get("name") or affiliate_code or "未綁定",
                "commission_rate": commission_rate,
                "order_count": 0,
                "sales_total": 0,
                "commission_total": 0,
                "orders": []
            })

            offer = offer_map.get(int(o.get("landing_offer_id") or 0)) or {}

            row["order_count"] += 1
            row["sales_total"] += total_amount
            row["commission_total"] += commission_amount

            row["orders"].append({
                "id": o.get("id"),
                "order_no": o.get("order_no") or o.get("MerchantTradeNo") or o.get("id"),
                "paid_at": format_tw_datetime(o.get("paid_at") or o.get("created_at")),
                "payment_method": format_payment_method(o),
                "receiver_name": o.get("receiver_name") or o.get("guest_name") or "—",
                "receiver_phone": o.get("receiver_phone") or o.get("guest_phone") or "—",
                "offer_name": offer.get("offer_name") or "—",
                "total_amount": total_amount,
                "commission_amount": commission_amount
            })

        rows = list(summary_map.values())
        rows.sort(key=lambda x: x["sales_total"], reverse=True)

        grand_order_count = sum(r["order_count"] for r in rows)
        grand_sales_total = sum(r["sales_total"] for r in rows)
        grand_commission_total = sum(r["commission_total"] for r in rows)

        return render_template(
            "admin_landing_page_report.html",
            rows=rows,
            pages=pages,
            affiliates=affiliates,
            selected_page_id=page_id_raw,
            selected_affiliate_code=affiliate_code_raw,
            date_from=date_from,
            date_to=date_to,
            grand_order_count=grand_order_count,
            grand_sales_total=grand_sales_total,
            grand_commission_total=grand_commission_total
        )

    # ======================================================
    # 後台：Landing Pages 管理
    # ======================================================
    @app.route("/admin0363/landing-pages")
    def admin_landing_pages():
        if not session.get("admin_logged_in"):
            return redirect("/admin0363")

        pages = (
            supabase.table("landing_pages")
            .select("*")
            .order("created_at", desc=True)
            .execute()
            .data or []
        )

        page_ids = [p["id"] for p in pages]
        offer_count_map = {}

        if page_ids:
            offers = (
                supabase.table("landing_page_offers")
                .select("id,landing_page_id")
                .in_("landing_page_id", page_ids)
                .execute()
                .data or []
            )
            for o in offers:
                pid = o.get("landing_page_id")
                offer_count_map[pid] = offer_count_map.get(pid, 0) + 1

        for p in pages:
            p["offer_count"] = offer_count_map.get(p["id"], 0)

        return render_template("admin_landing_pages.html", pages=pages)

    @app.route("/admin0363/landing-pages/new", methods=["GET", "POST"])
    def admin_landing_page_new():
        if not session.get("admin_logged_in"):
            return redirect("/admin0363")

        if request.method == "GET":
            return render_template(
                "admin_landing_page_form.html",
                mode="new",
                page={},
                offers=[]
            )

        page_data = parse_landing_page_form(request.form)

    # ===== 主圖：一張 → 自動產生桌面 + 手機 =====
        hero_file = request.files.get("hero_image_file")
        desktop_url, mobile_url = build_hero_images(hero_file)

        if desktop_url:
            page_data["hero_image"] = desktop_url
        if mobile_url:
            page_data["hero_image_mobile"] = mobile_url

    # ===== 副圖 =====
        secondary_files = request.files.getlist("secondary_image_files")
        uploaded_secondary = upload_secondary_images(secondary_files)

        existing = page_data.get("secondary_images_json") or []
        if uploaded_secondary:
            page_data["secondary_images_json"] = existing + uploaded_secondary

        # ===== 下單後圖片 =====
        middle_files = request.files.getlist("middle_image_files")
        uploaded_middle = upload_middle_images(middle_files)

        content_images = page_data.get("content_images_json") or {}
        after_buy = content_images.get("after_buy") or []

        if uploaded_middle:
            content_images["after_buy"] = after_buy + uploaded_middle
            page_data["content_images_json"] = content_images

        page_data["created_at"] = datetime.now(TW).isoformat()

        if not page_data["name"] or not page_data["slug"]:
            flash("請填寫頁面名稱與 slug", "error")
            return render_template(
                "admin_landing_page_form.html",
                mode="new",
                page=page_data,
                offers=[]
            )

        dup = (
            supabase.table("landing_pages")
            .select("id")
            .eq("slug", page_data["slug"])
            .execute()
            .data or []
        )
        if dup:
            flash("slug 已存在，請改一個", "error")
            return render_template(
                "admin_landing_page_form.html",
                mode="new",
                page=page_data,
                offers=[]
            )

        page_res = supabase.table("landing_pages").insert(page_data).execute()
        page_row = (page_res.data or [None])[0]

        if not page_row:
            flash("建立頁面失敗", "error")
            return redirect("/admin0363/landing-pages")

        offers = parse_landing_offers_form(request.form, page_row["id"])

        offer_image_files = request.files.getlist("offer_image_files[]")
        uploaded_offer_images = upload_offer_images(offer_image_files)

        for i, offer in enumerate(offers):
            if i < len(uploaded_offer_images) and uploaded_offer_images[i]:
                offer["image_url"] = uploaded_offer_images[i]

        if offers:
            supabase.table("landing_page_offers").insert(offers).execute()

        flash("一頁式頁面建立成功", "success")
        return redirect("/admin0363/landing-pages")

    @app.route("/admin0363/landing-pages/<int:page_id>/edit", methods=["GET", "POST"])
    def admin_landing_page_edit(page_id):
        if not session.get("admin_logged_in"):
            return redirect("/admin0363")

        page = get_landing_page_by_id(page_id)
        if not page:
            return "找不到頁面", 404

        if request.method == "GET":
            offers = get_landing_offers(page_id, active_only=False)
            page["faq_json"] = safe_json_loads(page.get("faq_json"), [])
            page["content_images_json"] = safe_json_loads(page.get("content_images_json"), {})
            page["sections_json"] = safe_json_loads(page.get("sections_json"), {})
            page["theme_json"] = safe_json_loads(page.get("theme_json"), {})
            page["secondary_images_json"] = safe_json_loads(page.get("secondary_images_json"), [])
            page["content_images_json"] = safe_json_loads(page.get("content_images_json"), {})
            page["buy_title"] = page.get("buy_title") or ""

            return render_template(
                "admin_landing_page_form.html",
                mode="edit",
                page=page,
                offers=offers
            )

        page_data = parse_landing_page_form(request.form)

        # ⭐ 保留原本 content_images_json（避免編輯時被清掉）
        new_content = page_data.get("content_images_json", {}) or {}
        page_data["content_images_json"] = new_content

        # ===== 主圖：一張 → 自動產生桌面 + 手機 =====
        hero_file = request.files.get("hero_image_file")
        desktop_url, mobile_url = build_hero_images(hero_file)

        if desktop_url:
            page_data["hero_image"] = desktop_url
        else:
            page_data["hero_image"] = (page.get("hero_image") or "").strip()

        if mobile_url:
            page_data["hero_image_mobile"] = mobile_url
        else:
            page_data["hero_image_mobile"] = (page.get("hero_image_mobile") or "").strip()

        # ===== 副圖：保留原本 + 新增上傳 =====
        existing_secondary = page_data.get("secondary_images_json") or []
        if not existing_secondary:
            existing_secondary = safe_json_loads(page.get("secondary_images_json"), [])

        secondary_files = request.files.getlist("secondary_image_files")
        uploaded_secondary = upload_secondary_images(secondary_files)

        if uploaded_secondary:
            page_data["secondary_images_json"] = existing_secondary + uploaded_secondary
        else:
            page_data["secondary_images_json"] = existing_secondary

            # ===== 下單後圖片：保留原本 + 新增上傳 =====
        middle_files = request.files.getlist("middle_image_files")
        uploaded_middle = upload_middle_images(middle_files)

        if uploaded_middle:
            after_buy = new_content.get("after_buy") or []
            new_content["after_buy"] = after_buy + uploaded_middle
            page_data["content_images_json"] = new_content
        
        if not page_data["name"] or not page_data["slug"]:
            flash("請填寫頁面名稱與 slug", "error")
            offers = parse_landing_offers_form(request.form, page_id)
            return render_template(
                "admin_landing_page_form.html",
                mode="edit",
                page=page_data,
                offers=offers
            )

        dup = (
            supabase.table("landing_pages")
            .select("id")
            .eq("slug", page_data["slug"])
            .execute()
            .data or []
        )
        dup = [r for r in dup if int(r["id"]) != int(page_id)]
        if dup:
            flash("slug 已存在，請改一個", "error")
            offers = parse_landing_offers_form(request.form, page_id)
            return render_template(
                "admin_landing_page_form.html",
                mode="edit",
                page=page_data,
                offers=offers
            )

        page_data["updated_at"] = datetime.now(TW).isoformat()

        supabase.table("landing_pages").update(page_data).eq("id", page_id).execute()
        supabase.table("landing_page_offers").delete().eq("landing_page_id", page_id).execute()

        offers = parse_landing_offers_form(request.form, page_id)

        offer_image_files = request.files.getlist("offer_image_files[]")
        uploaded_offer_images = upload_offer_images(offer_image_files)
        existing_offer_images = request.form.getlist("existing_offer_image_url[]")

        for i, offer in enumerate(offers):
            if i < len(uploaded_offer_images) and uploaded_offer_images[i]:
                offer["image_url"] = uploaded_offer_images[i]
            elif i < len(existing_offer_images) and existing_offer_images[i]:
                offer["image_url"] = existing_offer_images[i]

        if offers:
            supabase.table("landing_page_offers").insert(offers).execute()

        flash("一頁式頁面更新成功", "success")
        return redirect("/admin0363/landing-pages")

    @app.route("/admin0363/landing-pages/<int:page_id>/clone", methods=["POST"])
    def admin_landing_page_clone(page_id):
        if not session.get("admin_logged_in"):
            return redirect("/admin0363")

        page = get_landing_page_by_id(page_id)
        if not page:
            return "找不到頁面", 404

        offers = get_landing_offers(page_id, active_only=False)
        new_slug = slugify((page.get("slug") or "landing") + "-" + datetime.now(TW).strftime("%H%M%S"))

        new_page = {
            "name": (page.get("name") or "") + " 複製",
            "slug": new_slug,
            "title": page.get("title"),
            "subtitle": page.get("subtitle"),
            "hero_image": page.get("hero_image"),
            "hero_image_mobile": page.get("hero_image_mobile"),
            "description": page.get("description"),
            "faq_json": page.get("faq_json") or [],
            "sections_json": page.get("sections_json") or {},
            "cta_text": page.get("cta_text"),
            "cta_anchor": page.get("cta_anchor"),
            "theme_json": page.get("theme_json") or {},
            "affiliate_code": page.get("affiliate_code"),
            "is_active": False,
            "created_at": datetime.now(TW).isoformat(),
            "updated_at": datetime.now(TW).isoformat()
        }

        page_res = supabase.table("landing_pages").insert(new_page).execute()
        new_page_row = (page_res.data or [None])[0]
        if not new_page_row:
            flash("複製失敗", "error")
            return redirect("/admin0363/landing-pages")

        new_offers = []
        for o in offers:
            new_offers.append({
                "landing_page_id": new_page_row["id"],
                "offer_name": o.get("offer_name"),
                "subtitle": o.get("subtitle"),
                "badge": o.get("badge"),
                "product_type": o.get("product_type"),
                "product_id": o.get("product_id"),
                "bundle_id": o.get("bundle_id"),
                "image_url": o.get("image_url"),
                "products_json": o.get("products_json") or [],
                "price": o.get("price") or 0,
                "compare_at_price": o.get("compare_at_price"),
                "is_default": o.get("is_default") or False,
                "is_active": o.get("is_active") or False,
                "sort_order": o.get("sort_order") or 0
            })

        if new_offers:
            supabase.table("landing_page_offers").insert(new_offers).execute()

        flash("複製完成，請再進去修改內容", "success")
        return redirect("/admin0363/landing-pages")

    @app.route("/admin0363/landing-pages/<int:page_id>/toggle", methods=["POST"])
    def admin_landing_page_toggle(page_id):
        if not session.get("admin_logged_in"):
            return redirect("/admin0363")

        page = get_landing_page_by_id(page_id)
        if not page:
            return "找不到頁面", 404

        new_status = not bool(page.get("is_active"))
        supabase.table("landing_pages").update({
            "is_active": new_status,
            "updated_at": datetime.now(TW).isoformat()
        }).eq("id", page_id).execute()

        flash("狀態已更新", "success")
        return redirect("/admin0363/landing-pages")
    @app.route("/admin0363/landing-pages/<int:page_id>/delete", methods=["POST"])
    def admin_landing_page_delete(page_id):
        if not session.get("admin_logged_in"):
            return redirect("/admin0363")

        supabase.table("landing_page_offers") \
            .delete() \
            .eq("landing_page_id", page_id) \
            .execute()

        supabase.table("landing_pages") \
            .delete() \
            .eq("id", page_id) \
            .execute()

        flash("已刪除一頁式頁面", "success")
        return redirect("/admin0363/landing-pages")