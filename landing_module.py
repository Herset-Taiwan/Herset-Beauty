import json
import re
import random
from datetime import datetime
from flask import render_template, request, jsonify, session, redirect, flash


def register_landing_module(app, supabase, TW, generate_merchant_trade_no):
    # ======================================================
    # Helpers
    # ======================================================
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
            "affiliate_code": (form.get("affiliate_code") or "").strip(),
            "faq_json": faq_list,
            "sections_json": sections_json,
            "theme_json": theme_json,
            "is_active": form.get("is_active") == "1",
            "updated_at": datetime.now(TW).isoformat()
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

        return render_template("landing_page.html", page=page, offers=offers)

    @app.route("/api/landing-order", methods=["POST"])
    def api_landing_order():
        data = request.get_json(silent=True) or request.form

        slug = (data.get("slug") or "").strip()
        offer_id_raw = str(data.get("offer_id") or "").strip()
        qty_raw = str(data.get("qty") or "1").strip()

        receiver_name = (data.get("name") or "").strip()
        receiver_phone = (data.get("phone") or "").strip()
        receiver_address = (data.get("address") or "").strip()
        guest_email = (data.get("email") or "").strip()
        intended_payment_method = (data.get("payment_method") or "").strip().lower()

        if not slug:
            return jsonify({"ok": False, "error": "缺少頁面 slug"}), 400
        if not offer_id_raw.isdigit():
            return jsonify({"ok": False, "error": "方案錯誤"}), 400
        if not receiver_name or not receiver_phone or not receiver_address:
            return jsonify({"ok": False, "error": "請填寫完整收件資訊"}), 400

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
        # ===== 圖片上傳 =====
        hero_file = request.files.get("hero_image_file")
        mobile_file = request.files.get("hero_image_mobile_file")

        def upload_image(file):
            if not file or file.filename == "":
                return None

            filename = f"landing/{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"

            res = supabase.storage.from_("images").upload(filename, file.read())

            if hasattr(res, "error") and res.error:
                return None

            return supabase.storage.from_("images").get_public_url(filename)

        # 主圖
        uploaded_hero = upload_image(hero_file)
        if uploaded_hero:
            page_data["hero_image"] = uploaded_hero

        # 手機圖
        uploaded_mobile = upload_image(mobile_file)
        if uploaded_mobile:
            page_data["hero_image_mobile"] = uploaded_mobile
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
            page["sections_json"] = safe_json_loads(page.get("sections_json"), {})
            page["theme_json"] = safe_json_loads(page.get("theme_json"), {})

            return render_template(
                "admin_landing_page_form.html",
                mode="edit",
                page=page,
                offers=offers
            )

        page_data = parse_landing_page_form(request.form)

        # ===== 圖片上傳處理 =====
        hero_file = request.files.get("hero_image_file")
        mobile_file = request.files.get("hero_image_mobile_file")

        def upload_image(file):
            if not file or file.filename == "":
                return None

            filename = "landing/{0}_{1}".format(
                datetime.now(TW).strftime("%Y%m%d%H%M%S"),
                file.filename
            )

            res = supabase.storage.from_("images").upload(filename, file.read())

            if hasattr(res, "error") and res.error:
                return None

            return supabase.storage.from_("images").get_public_url(filename)

        uploaded_hero = upload_image(hero_file)
        if uploaded_hero:
            page_data["hero_image"] = uploaded_hero

        uploaded_mobile = upload_image(mobile_file)
        if uploaded_mobile:
            page_data["hero_image_mobile"] = uploaded_mobile

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

        supabase.table("landing_pages").update(page_data).eq("id", page_id).execute()
        supabase.table("landing_page_offers").delete().eq("landing_page_id", page_id).execute()

        offers = parse_landing_offers_form(request.form, page_id)
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
    
    # ======================================================
# 刪除 Landing Page
# ======================================================
@app.route("/admin0363/landing-pages/<int:page_id>/delete", methods=["POST"])
def admin_landing_page_delete(page_id):
    if not session.get("admin_logged_in"):
        return redirect("/admin0363")

    # 先刪子資料（方案）
    supabase.table("landing_page_offers") \
        .delete() \
        .eq("landing_page_id", page_id) \
        .execute()

    # 再刪主表
    supabase.table("landing_pages") \
        .delete() \
        .eq("id", page_id) \
        .execute()

    flash("已刪除一頁式頁面", "success")
    return redirect("/admin0363/landing-pages")