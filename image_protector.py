"""
image_protector.py — Consent-First Image Protection System
===========================================================
Core engine for registering, hashing, and protecting images.

Phase 1: Registration + Hashing
- Identity verification (phone OTP simulation)
- Consent recording
- Perceptual hash generation (pHash)
- Secure hash database (no original images stored)

Install:
    pip install imagehash Pillow cryptography qrcode pillow streamlit

Run:
    streamlit run image_protector.py
"""

import os
import json
import hashlib
import sqlite3
import random
import string
import datetime
from pathlib import Path
from io import BytesIO

import streamlit as st
from PIL import Image
import imagehash

# Import payment system
try:
    from payments import (PLANS, get_user_plan, can_protect_more,
                          initiate_payment, verify_payment,
                          get_subscription_status)
    PAYMENTS_ENABLED = True
except ImportError:
    PAYMENTS_ENABLED = False

# Import takedown system
try:
    from takedown import generate_takedown, get_email_subject
    TAKEDOWN_ENABLED = True
except ImportError:
    TAKEDOWN_ENABLED = False

# Import takedown system
try:
    from takedown import (generate_takedown, generate_police_report,
                          PLATFORMS)
    TAKEDOWN_ENABLED = True
except ImportError:
    TAKEDOWN_ENABLED = False

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH       = "./image_protection.db"
UPLOAD_FOLDER = "./protected_assets"
Path(UPLOAD_FOLDER).mkdir(exist_ok=True)

APP_VERSION   = "1.0.0"
HASH_DISTANCE = 8  # pHash similarity threshold (0=identical, 10=similar)

st.set_page_config(
    page_title="Image Protection System",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Mobile CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
.main .block-container { max-width: 520px; margin: 0 auto; padding: 1rem; }
.stButton > button { width: 100%; min-height: 48px; border-radius: 12px; font-weight: 600; }
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #4A3AFF, #7B6BFF);
    color: white; border: none;
}
.stTextInput > div > div > input { border-radius: 10px; min-height: 48px; }
.shield-card {
    background: linear-gradient(135deg, #1a1a2e, #16213e);
    border-radius: 16px; padding: 1.5rem; text-align: center;
    color: white; margin-bottom: 1rem;
}
.stat-box {
    border: 1px solid var(--color-border-tertiary);
    border-radius: 12px; padding: 1rem; text-align: center;
}
.consent-box {
    border: 2px solid #4A3AFF; border-radius: 12px;
    padding: 1rem; background: #f8f7ff;
}
</style>
""", unsafe_allow_html=True)

# ── Database ──────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id     TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            phone       TEXT NOT NULL UNIQUE,
            email       TEXT,
            user_type   TEXT DEFAULT 'individual',
            otp_verified INTEGER DEFAULT 0,
            consent_signed INTEGER DEFAULT 0,
            consent_date TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            total_protected INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS protected_hashes (
            hash_id         TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL,
            phash           TEXT NOT NULL,
            dhash           TEXT NOT NULL,
            ahash           TEXT NOT NULL,
            image_label     TEXT,
            image_size      TEXT,
            registered_at   TEXT DEFAULT (datetime('now')),
            is_active       INTEGER DEFAULT 1,
            detection_count INTEGER DEFAULT 0,
            last_detected   TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );

        CREATE TABLE IF NOT EXISTS detections (
            detection_id  TEXT PRIMARY KEY,
            hash_id       TEXT NOT NULL,
            user_id       TEXT NOT NULL,
            platform      TEXT,
            url           TEXT,
            detected_at   TEXT DEFAULT (datetime('now')),
            similarity    REAL,
            status        TEXT DEFAULT 'new',
            takedown_sent INTEGER DEFAULT 0,
            evidence_path TEXT
        );

        CREATE TABLE IF NOT EXISTS otp_log (
            phone       TEXT PRIMARY KEY,
            otp_code    TEXT,
            created_at  TEXT,
            verified    INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_conn():
    return sqlite3.connect(DB_PATH)

def generate_id(prefix="USR"):
    ts = datetime.datetime.now().strftime("%y%m%d%H%M%S")
    rand = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"{prefix}-{ts}-{rand}"

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp(phone: str, otp: str):
    """In production: use Twilio. For now — show in UI for testing."""
    conn = get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO otp_log (phone, otp_code, created_at, verified)
        VALUES (?, ?, datetime('now'), 0)
    """, (phone, otp))
    conn.commit()
    conn.close()
    return True

def verify_otp(phone: str, entered_otp: str) -> bool:
    # Simple: compare against session state OTP directly
    session_otp = st.session_state.get("otp_code", "")
    if not session_otp:
        return False
    return entered_otp.strip() == str(session_otp).strip()

def compute_hashes(image: Image.Image) -> dict:
    """Compute multiple perceptual hashes for robust matching."""
    img_rgb = image.convert("RGB")
    return {
        "phash": str(imagehash.phash(img_rgb)),       # Perceptual hash (best for photos)
        "dhash": str(imagehash.dhash(img_rgb)),       # Difference hash (good for crops)
        "ahash": str(imagehash.average_hash(img_rgb)),# Average hash (fast baseline)
    }

def register_image(user_id: str, image: Image.Image, label: str) -> dict:
    """Register an image — stores ONLY hashes, never the image."""
    hashes   = compute_hashes(image)
    hash_id  = generate_id("IMG")
    size_str = f"{image.width}x{image.height}"

    conn = get_conn()
    # Check for duplicate
    existing = conn.execute(
        "SELECT hash_id FROM protected_hashes WHERE phash=? AND user_id=? AND is_active=1",
        (hashes["phash"], user_id)
    ).fetchone()

    if existing:
        conn.close()
        return {"status": "duplicate", "hash_id": existing[0]}

    conn.execute("""
        INSERT INTO protected_hashes
            (hash_id, user_id, phash, dhash, ahash, image_label, image_size)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (hash_id, user_id, hashes["phash"], hashes["dhash"],
          hashes["ahash"], label, size_str))
    conn.execute(
        "UPDATE users SET total_protected = total_protected + 1 WHERE user_id=?",
        (user_id,)
    )
    conn.commit()
    conn.close()
    return {"status": "registered", "hash_id": hash_id, "hashes": hashes}

def check_image(image: Image.Image) -> list:
    """Check if an image matches any protected hash in the database."""
    hashes   = compute_hashes(image)
    test_p   = imagehash.hex_to_hash(hashes["phash"])
    test_d   = imagehash.hex_to_hash(hashes["dhash"])
    matches  = []

    conn = get_conn()
    rows = conn.execute("""
        SELECT h.hash_id, h.phash, h.dhash, h.image_label, h.user_id,
               u.name, u.phone
        FROM protected_hashes h
        JOIN users u ON h.user_id = u.user_id
        WHERE h.is_active = 1
    """).fetchall()
    conn.close()

    for row in rows:
        hash_id, db_phash, db_dhash, label, uid, name, phone = row
        try:
            dist_p = test_p - imagehash.hex_to_hash(db_phash)
            dist_d = test_d - imagehash.hex_to_hash(db_dhash)
            avg_dist = (dist_p + dist_d) / 2
            if avg_dist <= HASH_DISTANCE:
                similarity = max(0, 100 - (avg_dist / 64 * 100))
                matches.append({
                    "hash_id":    hash_id,
                    "label":      label,
                    "owner_name": name,
                    "similarity": round(similarity, 1),
                    "distance":   avg_dist,
                })
        except Exception:
            continue

    matches.sort(key=lambda x: x["similarity"], reverse=True)
    return matches

def get_user_stats(user_id: str) -> dict:
    conn = get_conn()
    stats = conn.execute("""
        SELECT
            total_protected,
            (SELECT COUNT(*) FROM detections WHERE user_id=?) as total_detections,
            (SELECT COUNT(*) FROM detections WHERE user_id=? AND status='new') as new_detections
        FROM users WHERE user_id=?
    """, (user_id, user_id, user_id)).fetchone()
    conn.close()
    return {
        "protected": stats[0] if stats else 0,
        "detections": stats[1] if stats else 0,
        "new_alerts": stats[2] if stats else 0,
    }

# ── Session state ─────────────────────────────────────────────────────────────
if "page" not in st.session_state:
    st.session_state.page = "home"
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "otp_sent" not in st.session_state:
    st.session_state.otp_sent = False
if "otp_code" not in st.session_state:
    st.session_state.otp_code = None

# ── Navigation ────────────────────────────────────────────────────────────────
def nav(page):
    st.session_state.page = page
    st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: HOME
# ══════════════════════════════════════════════════════════════════════════════
if st.session_state.page == "home":
    st.markdown("""
    <div style='text-align:center; padding: 1.5rem 0 1rem 0;'>
        <div style='font-size:3rem;'>🛡️</div>
        <div style='font-size:1.5rem; font-weight:700; color:#4A3AFF;'>ImageGuard</div>
        <div style='font-size:0.9rem; color:#666; margin-top:0.3rem;'>
            Consent-first image protection
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("**What this does:**")
    st.markdown("""
- 🔒 **Protects your images** before they spread online
- 🔍 **Detects matches** across Telegram, X, Reddit
- 📋 **Logs evidence** automatically if your image is found
- ⚡ **Sends takedown** requests on your behalf
- 🚫 **Never stores** your actual image — only a fingerprint
""")
    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📝 Register", type="primary"):
            nav("register")
    with col2:
        if st.button("🔑 Log in"):
            nav("login")

    st.markdown("---")
    if st.button("🔍 Check if image is protected"):
        nav("check")

    st.markdown("""
    <div style='text-align:center; font-size:0.75rem; color:#999; margin-top:1rem;'>
    Your privacy is our priority. We store fingerprints, not photos.<br>
    Only YOU can register YOUR images.
    </div>
    """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: REGISTER
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "register":
    st.markdown("### 📝 Create your account")
    st.caption("Step 1 of 3 — Identity verification")

    name = st.text_input("Full name", placeholder="e.g. Micah Godwin")
    phone = st.text_input("Phone number", placeholder="+234 xxx xxx xxxx")
    email = st.text_input("Email (optional)", placeholder="your@email.com")
    user_type = st.selectbox("Account type", ["Individual", "Organisation (NGO/School/Hospital)"])

    if not st.session_state.otp_sent:
        if st.button("📱 Send verification code", type="primary"):
            if not name or not phone:
                st.error("Please enter your name and phone number.")
            else:
                otp = generate_otp()
                st.session_state.otp_code = otp
                st.session_state.reg_data = {
                    "name": name, "phone": phone,
                    "email": email, "user_type": user_type.split()[0].lower()
                }
                send_otp(phone, otp)
                st.session_state.otp_sent = True
                st.rerun()
    else:
        st.success(f"✅ Code sent to {phone}")

        # Development mode — show OTP
        st.info(f"🔑 **Development mode — your OTP: `{st.session_state.otp_code}`**\n\n"
                f"In production this will be sent via SMS (Twilio).")

        entered = st.text_input("Enter 6-digit code", placeholder="000000",
                                max_chars=6)

        if st.button("✅ Verify and continue", type="primary"):
            if verify_otp(st.session_state.reg_data["phone"], entered):
                # Create user
                user_id = generate_id("USR")
                conn = get_conn()
                try:
                    conn.execute("""
                        INSERT INTO users (user_id, name, phone, email, user_type, otp_verified)
                        VALUES (?, ?, ?, ?, ?, 1)
                    """, (user_id,
                          st.session_state.reg_data["name"],
                          st.session_state.reg_data["phone"],
                          st.session_state.reg_data["email"],
                          st.session_state.reg_data["user_type"]))
                    conn.commit()
                    st.session_state.user_id = user_id
                    st.session_state.otp_sent = False
                    nav("consent")
                except sqlite3.IntegrityError:
                    st.error("This phone number is already registered. Please log in.")
                finally:
                    conn.close()
            else:
                st.error("Incorrect code. Please try again.")

        if st.button("← Back"):
            st.session_state.otp_sent = False
            nav("home")

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: CONSENT
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "consent":
    st.markdown("### 📋 Consent agreement")
    st.caption("Step 2 of 3 — You must agree before protecting any images")

    st.markdown("""
    <div class='consent-box'>
    <strong>ImageGuard Consent Agreement</strong><br><br>
    By using this service, I confirm that:<br><br>
    ✅ I am the <strong>rightful owner</strong> of any images I register<br>
    ✅ I am registering images of <strong>myself only</strong><br>
    ✅ I understand only <strong>fingerprints are stored</strong>, not my photos<br>
    ✅ I consent to automated <strong>monitoring and takedown</strong> requests<br>
    ✅ I will <strong>not misuse</strong> this service to monitor others without consent<br>
    ✅ I am <strong>18 years or older</strong><br><br>
    <em>Misuse of this service to register images of other people without their
    consent is a violation of terms and may be reported to authorities.</em>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("")
    agreed = st.checkbox("I have read and agree to the terms above")

    if st.button("✅ I agree — continue", type="primary", disabled=not agreed):
        conn = get_conn()
        conn.execute("""
            UPDATE users SET consent_signed=1, consent_date=datetime('now')
            WHERE user_id=?
        """, (st.session_state.user_id,))
        conn.commit()
        conn.close()
        nav("dashboard")

    if st.button("← Cancel"):
        # Delete unfinished registration
        conn = get_conn()
        conn.execute("DELETE FROM users WHERE user_id=?",
                     (st.session_state.user_id,))
        conn.commit()
        conn.close()
        st.session_state.user_id = None
        nav("home")

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: LOGIN
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "login":
    st.markdown("### 🔑 Log in")

    phone = st.text_input("Phone number", placeholder="+234 xxx xxx xxxx")

    if not st.session_state.otp_sent:
        if st.button("📱 Send login code", type="primary"):
            conn = get_conn()
            user = conn.execute(
                "SELECT user_id, name FROM users WHERE phone=?", (phone,)
            ).fetchone()
            conn.close()
            if user:
                otp = generate_otp()
                st.session_state.otp_code = otp
                st.session_state.login_user = {"user_id": user[0], "name": user[1], "phone": phone}
                send_otp(phone, otp)
                st.session_state.otp_sent = True
                st.rerun()
            else:
                st.error("No account found with this number. Please register first.")
    else:
        st.success(f"✅ Code sent!")
        st.info(f"🔑 **Development mode OTP: `{st.session_state.otp_code}`**")
        entered = st.text_input("Enter 6-digit code", max_chars=6)

        if st.button("✅ Log in", type="primary"):
            if verify_otp(st.session_state.login_user["phone"], entered):
                st.session_state.user_id = st.session_state.login_user["user_id"]
                st.session_state.otp_sent = False
                nav("dashboard")
            else:
                st.error("Incorrect code.")

    if st.button("← Back"):
        st.session_state.otp_sent = False
        nav("home")

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "dashboard":
    if not st.session_state.user_id:
        nav("home")

    conn = get_conn()
    user = conn.execute(
        "SELECT name, user_type, total_protected FROM users WHERE user_id=?",
        (st.session_state.user_id,)
    ).fetchone()
    conn.close()

    if not user:
        nav("home")

    name, utype, total = user
    stats = get_user_stats(st.session_state.user_id)

    st.markdown(f"""
    <div style='text-align:center; padding:1rem 0;'>
        <div style='font-size:1.3rem; font-weight:700;'>👋 {name}</div>
        <div style='font-size:0.8rem; color:#666;'>{utype.title()} account</div>
    </div>
    """, unsafe_allow_html=True)

    # Stats
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"""<div class='stat-box'>
            <div style='font-size:1.5rem;font-weight:700;color:#4A3AFF;'>{stats['protected']}</div>
            <div style='font-size:0.75rem;color:#666;'>Protected</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class='stat-box'>
            <div style='font-size:1.5rem;font-weight:700;color:#E85D24;'>{stats['detections']}</div>
            <div style='font-size:0.75rem;color:#666;'>Detections</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        alert_color = "#E85D24" if stats['new_alerts'] > 0 else "#22c55e"
        st.markdown(f"""<div class='stat-box'>
            <div style='font-size:1.5rem;font-weight:700;color:{alert_color};'>{stats['new_alerts']}</div>
            <div style='font-size:0.75rem;color:#666;'>New alerts</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    if st.button("🔒 Protect a new image", type="primary"):
        nav("protect")

    if st.button("🔍 Check an image"):
        nav("check")

    if st.button("📋 My protected images"):
        nav("my_images")

    if st.button("🚨 Alerts and detections"):
        nav("alerts")

    if st.button("⭐ Upgrade plan"):
        nav("upgrade")

    st.markdown("---")
    if st.button("🚪 Log out"):
        st.session_state.user_id = None
        nav("home")

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: PROTECT IMAGE
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "protect":
    if not st.session_state.user_id:
        nav("home")

    st.markdown("### 🔒 Protect your image")
    st.caption("Only your fingerprint is stored — never the original photo")

    st.info("⚠️ **Consent reminder:** Only register images of yourself. "
            "Registering someone else's image without their consent violates our terms.")

    # Show plan limit
    if PAYMENTS_ENABLED:
        can, msg = can_protect_more(st.session_state.user_id)
        if not can:
            st.error(f"🚫 {msg}")
            if st.button("⭐ Upgrade now"):
                nav("upgrade")
            st.stop()
        else:
            st.caption(f"📊 {msg}")

    label = st.text_input("Image label (private — only you see this)",
                           placeholder="e.g. Profile photo 2024, Beach photo")

    uploaded = st.file_uploader(
        "Upload your image",
        type=["jpg","jpeg","png","webp","bmp"],
        help="The image is processed locally — never uploaded to any server"
    )

    if uploaded:
        image = Image.open(uploaded)

        # Show preview (blurred for privacy)
        col1, col2 = st.columns([1,1])
        with col1:
            st.image(image, caption="Your image (preview)", use_container_width=True)
        with col2:
            hashes = compute_hashes(image)
            st.markdown("**Fingerprint preview:**")
            st.code(f"pHash: {hashes['phash'][:16]}...\ndHash: {hashes['dhash'][:16]}...\nSize:  {image.width}×{image.height}px")
            st.caption("This fingerprint is what gets stored — not your photo")

        if st.button("🔒 Register and protect", type="primary"):
            if not label:
                st.error("Please add a label so you can identify this image later.")
            else:
                result = register_image(st.session_state.user_id, image, label)
                if result["status"] == "registered":
                    st.success(f"""
✅ **Image protected successfully!**

Your image fingerprint has been registered.
The system will now monitor for any matches online.

🆔 Protection ID: `{result['hash_id']}`
""")
                    st.balloons()
                elif result["status"] == "duplicate":
                    st.warning("This image is already protected in your account.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("← Dashboard"):
            nav("dashboard")
    with col2:
        if st.button("Protect another →"):
            st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: CHECK IMAGE
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "check":
    st.markdown("### 🔍 Check if image is protected")
    st.caption("Upload any image to see if it matches a protected fingerprint")

    uploaded = st.file_uploader(
        "Upload image to check",
        type=["jpg","jpeg","png","webp","bmp"],
        key="check_upload"
    )

    if uploaded:
        image = Image.open(uploaded)
        st.image(image, caption="Checking this image...", use_container_width=True)

        with st.spinner("Scanning database..."):
            matches = check_image(image)

        if matches:
            st.error(f"🚨 **Match found! This image is protected.**")
            for m in matches:
                st.markdown(f"""
**Owner:** {m['owner_name']}
**Image:** {m['label']}
**Similarity:** {m['similarity']}%
**Protection ID:** `{m['hash_id']}`
""")
                st.warning("⚠️ Sharing this image without the owner's consent may violate their rights and result in legal action.")
        else:
            st.success("✅ No matches found in the protection database.")
            st.caption("This image has not been registered for protection.")

    if st.button("← Back"):
        if st.session_state.user_id:
            nav("dashboard")
        else:
            nav("home")

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: MY IMAGES
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "my_images":
    if not st.session_state.user_id:
        nav("home")

    st.markdown("### 📋 My protected images")

    conn = get_conn()
    images = conn.execute("""
        SELECT hash_id, image_label, image_size, registered_at,
               detection_count, is_active
        FROM protected_hashes
        WHERE user_id=?
        ORDER BY registered_at DESC
    """, (st.session_state.user_id,)).fetchall()
    conn.close()

    if not images:
        st.info("You haven't protected any images yet.")
        if st.button("🔒 Protect your first image", type="primary"):
            nav("protect")
    else:
        st.caption(f"{len(images)} image(s) protected")
        for img in images:
            hid, label, size, reg_at, det_count, is_active = img
            status_emoji = "🟢" if is_active else "🔴"
            alert_badge = f" 🚨 {det_count} detections" if det_count > 0 else ""

            with st.expander(f"{status_emoji} {label}{alert_badge}"):
                st.markdown(f"""
**Protection ID:** `{hid}`
**Image size:** {size}
**Registered:** {reg_at[:16]}
**Detections:** {det_count}
**Status:** {'Active' if is_active else 'Deactivated'}
""")
                if is_active:
                    if st.button(f"Deactivate protection", key=f"deact_{hid}"):
                        conn = get_conn()
                        conn.execute(
                            "UPDATE protected_hashes SET is_active=0 WHERE hash_id=?",
                            (hid,)
                        )
                        conn.commit()
                        conn.close()
                        st.rerun()

    if st.button("← Dashboard"):
        nav("dashboard")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: TAKEDOWN
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "takedown":
    if not st.session_state.user_id:
        nav("home")

    det_id = st.session_state.get("takedown_det_id", "")
    if not det_id:
        nav("alerts")

    st.markdown("### 📤 Send Takedown Notice")

    # Get user info
    conn = get_conn()
    user = conn.execute(
        "SELECT name, email, phone FROM users WHERE user_id=?",
        (st.session_state.user_id,)
    ).fetchone()
    conn.close()

    if not user:
        nav("dashboard")

    name, email, phone = user

    # Platform selection
    if TAKEDOWN_ENABLED:
        platform_options = {v["name"]: k for k, v in PLATFORMS.items()}
        selected = st.selectbox("Select platform", list(platform_options.keys()))
        platform_key = platform_options[selected]

        owner_address = st.text_input(
            "Your address (for legal letter)",
            placeholder="e.g. 123 Lagos Street, Abuja, Nigeria"
        )

        st.markdown("---")
        st.subheader("📋 Preview takedown letter")

        if owner_address:
            result = generate_takedown(
                det_id, platform_key,
                name, email or f"{phone}@shieldmark.africa",
                owner_address, phone
            )

            if "error" not in result:
                with st.expander("View full letter", expanded=True):
                    st.text(result["letter"])

                st.success(f"✅ Letter generated — Ref: {result['ref']}")

                col1, col2 = st.columns(2)
                with col1:
                    st.download_button(
                        "⬇️ Download letter",
                        result["letter"],
                        file_name=f"{result['ref']}.txt",
                        mime="text/plain"
                    )
                with col2:
                    st.markdown(f"📧 **Send to:** {result['send_to']}")
                    st.markdown(f"🔗 **Or use form:** [Click here]({result['form_url']})")

                st.markdown("---")
                st.subheader("🚔 Also report to Nigerian Police?")
                if st.button("Generate police complaint letter"):
                    police = generate_police_report(
                        det_id, name, owner_address, phone
                    )
                    st.download_button(
                        "⬇️ Download police complaint",
                        police,
                        file_name=f"police_{det_id[-8:]}.txt",
                        mime="text/plain"
                    )
                    st.info("Submit to: EFCC Cybercrime Unit or nearest police command")
    else:
        st.warning("Takedown module not loaded. Ensure takedown.py is in the same folder.")

    if st.button("← Back to alerts"):
        nav("alerts")

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: UPGRADE
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "upgrade":
    if not st.session_state.user_id:
        nav("home")

    st.markdown("### ⭐ Upgrade your plan")

    # Check if returning from payment
    params = st.query_params
    if "demo_payment" in params:
        ref = params.get("ref", "")
        if ref and PAYMENTS_ENABLED:
            result = verify_payment(ref)
            if result.get("status") == "success":
                st.success(f"✅ Payment successful! You are now on the **{result['plan'].title()}** plan.")
                st.balloons()
        st.query_params.clear()

    if PAYMENTS_ENABLED:
        sub = get_subscription_status(st.session_state.user_id)
        st.info(f"Current plan: **{sub['plan_name']}** — {sub['limit']} images")

    # Get user email
    conn = get_conn()
    user = conn.execute(
        "SELECT email, phone FROM users WHERE user_id=?",
        (st.session_state.user_id,)
    ).fetchone()
    conn.close()
    user_email = user[0] if user and user[0] else f"{user[1]}@shieldmark.africa"

    # Plan cards
    for plan_key, plan in PLANS.items():
        is_current = PAYMENTS_ENABLED and get_user_plan(
            st.session_state.user_id)["plan"] == plan_key

        border = "2px solid #4A3AFF" if not is_current else "2px solid #22c55e"
        label  = "✅ Current plan" if is_current else f"₦{plan['price_ngn']:,}/month"

        with st.expander(
            f"{plan['emoji']} {plan['name']} — {label}",
            expanded=(plan_key == "personal")
        ):
            for feature in plan["features"]:
                st.markdown(f"✓ {feature}")

            if not is_current:
                if st.button(
                    f"Subscribe — ₦{plan['price_ngn']:,}/month",
                    key=f"sub_{plan_key}",
                    type="primary"
                ):
                    if PAYMENTS_ENABLED:
                        result = initiate_payment(
                            st.session_state.user_id,
                            plan_key, user_email
                        )
                        if result.get("status") == "demo":
                            st.info(f"🧪 Demo mode — click to simulate payment:")
                            st.markdown(f"[Complete demo payment]({result['payment_url']})")
                        elif result.get("status") == "redirect":
                            st.markdown(f"[Pay ₦{plan['price_ngn']:,} securely via Paystack]({result['payment_url']})")
                        else:
                            st.error(result.get("error", "Payment error"))
                    else:
                        st.warning("Add payments.py to enable subscriptions.")

    st.markdown("---")
    st.caption("💳 Payments powered by Paystack — Nigeria's leading payment gateway")
    st.caption("🔒 Your card details are never stored by ShieldMark")

    if st.button("← Dashboard"):
        nav("dashboard")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: ALERTS
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "alerts":
    if not st.session_state.user_id:
        nav("home")

    st.markdown("### 🚨 Alerts and detections")

    conn = get_conn()
    detections = conn.execute("""
        SELECT d.detection_id, d.platform, d.url, d.detected_at,
               d.similarity, d.status, d.takedown_sent,
               h.image_label
        FROM detections d
        JOIN protected_hashes h ON d.hash_id = h.hash_id
        WHERE d.user_id=?
        ORDER BY d.detected_at DESC
    """, (st.session_state.user_id,)).fetchall()
    conn.close()

    if not detections:
        st.success("✅ No detections yet. Your images are safe.")
        st.caption("The system scans platforms every 6 hours for matches.")

        # Demo detection for testing
        if st.button("🧪 Simulate a test detection"):
            conn = get_conn()
            images = conn.execute(
                "SELECT hash_id FROM protected_hashes WHERE user_id=? AND is_active=1 LIMIT 1",
                (st.session_state.user_id,)
            ).fetchone()
            if images:
                det_id = generate_id("DET")
                conn.execute("""
                    INSERT INTO detections
                        (detection_id, hash_id, user_id, platform, url,
                         similarity, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'new')
                """, (det_id, images[0], st.session_state.user_id,
                      "Telegram", "https://t.me/example/12345", 94.7))
                conn.execute(
                    "UPDATE protected_hashes SET detection_count=detection_count+1 WHERE hash_id=?",
                    (images[0],)
                )
                conn.commit()
                conn.close()
                st.rerun()
            else:
                conn.close()
                st.warning("Register an image first to test detections.")
    else:
        for det in detections:
            det_id, platform, url, det_at, sim, status, takedown, label = det
            is_new = status == "new"
            with st.expander(
                f"{'🔴 NEW: ' if is_new else ''}{platform} — {label} ({sim}% match)",
                expanded=is_new
            ):
                st.markdown(f"""
**Platform:** {platform}
**Detected at:** {det_at[:16]}
**Similarity:** {sim}%
**URL:** {url}
**Status:** {status.title()}
**Takedown sent:** {'Yes ✅' if takedown else 'No'}
""")
                if status == "new":
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("📤 Generate takedown", key=f"td_{det_id}"):
                            st.session_state["takedown_det_id"] = det_id
                            nav("takedown")
                    with col2:
                        if st.button("📋 Download evidence", key=f"ev_{det_id}"):
                            evidence = f"""IMAGE PROTECTION EVIDENCE REPORT
{'='*50}
Detection ID:  {det_id}
Image:         {label}
Platform:      {platform}
URL:           {url}
Detected:      {det_at}
Similarity:    {sim}%
{'='*50}
This report was generated by ImageGuard.
For legal use — do not alter this document.
"""
                            st.download_button(
                                "⬇️ Download PDF evidence",
                                evidence,
                                file_name=f"evidence_{det_id}.txt",
                                mime="text/plain",
                                key=f"dl_{det_id}"
                            )

    if st.button("← Dashboard"):
        nav("dashboard")
