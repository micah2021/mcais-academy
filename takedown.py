"""
takedown.py — ShieldMark Africa: DMCA Takedown Generator
=========================================================
Generates professional DMCA takedown letters for platforms.
Works for: Telegram, Facebook, Instagram, Twitter/X, TikTok,
           WhatsApp (Meta), YouTube, Google, Reddit, and more.

Usage:
    from takedown import generate_takedown, send_takedown
"""

import sqlite3
import datetime
import os
from pathlib import Path

DB_PATH      = "./image_protection.db"
EVIDENCE_DIR = "./evidence"
Path(EVIDENCE_DIR).mkdir(exist_ok=True)


# ── Platform contact info ─────────────────────────────────────────────────────
PLATFORM_CONTACTS = {
    "telegram": {
        "name":    "Telegram",
        "email":   "abuse@telegram.org",
        "url":     "https://telegram.org/support",
        "process": "Email abuse@telegram.org with the channel/message link.",
        "response_days": 3,
    },
    "facebook": {
        "name":    "Facebook / Meta",
        "email":   "ip@meta.com",
        "url":     "https://www.facebook.com/help/contact/1758255661104383",
        "process": "Use Meta's IP reporting form or email ip@meta.com.",
        "response_days": 7,
    },
    "instagram": {
        "name":    "Instagram / Meta",
        "email":   "ip@meta.com",
        "url":     "https://help.instagram.com/contact/372592039493026",
        "process": "Use Instagram's copyright form.",
        "response_days": 7,
    },
    "twitter": {
        "name":    "Twitter / X",
        "email":   "copyright@twitter.com",
        "url":     "https://help.twitter.com/forms/dmca",
        "process": "Submit via X DMCA form or email copyright@twitter.com.",
        "response_days": 5,
    },
    "tiktok": {
        "name":    "TikTok",
        "email":   "copyright@tiktok.com",
        "url":     "https://www.tiktok.com/legal/report/Copyright",
        "process": "Use TikTok's copyright reporting form.",
        "response_days": 5,
    },
    "youtube": {
        "name":    "YouTube / Google",
        "email":   "copyright@youtube.com",
        "url":     "https://www.youtube.com/copyright_complaint_form",
        "process": "Use YouTube's copyright complaint form.",
        "response_days": 7,
    },
    "google": {
        "name":    "Google",
        "email":   "dmca-agent@google.com",
        "url":     "https://support.google.com/legal/troubleshooter/1114905",
        "process": "Submit via Google's legal removal request form.",
        "response_days": 10,
    },
    "reddit": {
        "name":    "Reddit",
        "email":   "copyright@reddit.com",
        "url":     "https://www.reddit.com/report",
        "process": "Email copyright@reddit.com with the post URL.",
        "response_days": 5,
    },
    "whatsapp": {
        "name":    "WhatsApp / Meta",
        "email":   "ip@meta.com",
        "url":     "https://www.whatsapp.com/contact",
        "process": "Email ip@meta.com. Note: WhatsApp is end-to-end encrypted — report group links.",
        "response_days": 10,
    },
    "other": {
        "name":    "Online Platform",
        "email":   "abuse@[platform].com",
        "url":     "N/A",
        "process": "Email the platform's abuse or DMCA contact.",
        "response_days": 14,
    },
}


def get_conn():
    return sqlite3.connect(DB_PATH)


def generate_takedown(detection_id: str,
                      owner_name: str,
                      owner_email: str,
                      owner_address: str = "Nigeria") -> dict:
    """
    Generate a DMCA takedown letter for a detection.
    Returns letter text + platform contact info.
    """
    conn = get_conn()
    det  = conn.execute("""
        SELECT d.detection_id, d.platform, d.url, d.detected_at,
               d.similarity, h.image_label, h.hash_id, h.registered_at
        FROM detections d
        JOIN protected_hashes h ON d.hash_id = h.hash_id
        WHERE d.detection_id = ?
    """, (detection_id,)).fetchone()
    conn.close()

    if not det:
        return {"error": "Detection not found"}

    (det_id, platform, url, detected_at,
     similarity, label, hash_id, registered_at) = det

    # Get platform info
    platform_key = platform.lower().split()[0]
    plat_info    = PLATFORM_CONTACTS.get(
        platform_key, PLATFORM_CONTACTS["other"]
    )

    today    = datetime.datetime.now().strftime("%B %d, %Y")
    reg_date = registered_at[:10] if registered_at else "prior to detection"

    letter = f"""
DMCA TAKEDOWN NOTICE
Digital Millennium Copyright Act (17 U.S.C. § 512)

Date: {today}

To: {plat_info['name']} Legal / Abuse Team
Email: {plat_info['email']}

─────────────────────────────────────────────────
I. IDENTIFICATION OF COMPLAINING PARTY
─────────────────────────────────────────────────

Full Name:    {owner_name}
Email:        {owner_email}
Address:      {owner_address}
Country:      Nigeria

─────────────────────────────────────────────────
II. IDENTIFICATION OF COPYRIGHTED WORK
─────────────────────────────────────────────────

I am the original creator and copyright owner of the following
work(s):

  Description:     {label}
  Protection ID:   {hash_id}
  Registration:    {reg_date}
  Fingerprint:     Perceptual hash registered with ShieldMark Africa
                   (shieldmark.africa) prior to the infringing upload.

─────────────────────────────────────────────────
III. IDENTIFICATION OF INFRINGING MATERIAL
─────────────────────────────────────────────────

The following material infringes my copyright and appears without
my knowledge or consent:

  Platform:        {plat_info['name']}
  Infringing URL:  {url}
  Detected:        {detected_at[:16] if detected_at else today}
  Match confidence:{similarity}% (automated perceptual hash analysis)

This content was posted WITHOUT my permission and constitutes a
violation of my exclusive rights under copyright law.

─────────────────────────────────────────────────
IV. STATEMENT OF GOOD FAITH
─────────────────────────────────────────────────

I have a good faith belief that the use of the described material
in the manner complained of is not authorised by the copyright
owner, its agent, or the law.

─────────────────────────────────────────────────
V. STATEMENT OF ACCURACY
─────────────────────────────────────────────────

I swear, under penalty of perjury, that the information in this
notification is accurate, and that I am the copyright owner or am
authorised to act on behalf of the copyright owner.

─────────────────────────────────────────────────
VI. REQUESTED ACTION
─────────────────────────────────────────────────

I hereby request that you:

  1. Immediately remove or disable access to the infringing content
  2. Notify the uploader of this takedown notice
  3. Preserve all associated user data per applicable law
  4. Confirm removal to my email address above

─────────────────────────────────────────────────

Sincerely,

{owner_name}
Copyright Owner
{today}

─────────────────────────────────────────────────
EVIDENCE REFERENCE
─────────────────────────────────────────────────
Detection ID:    {det_id}
Hash ID:         {hash_id}
Similarity:      {similarity}%
Generated by:    ShieldMark Africa — shieldmark.africa
─────────────────────────────────────────────────

NOTE: This notice is generated by ShieldMark Africa's automated
content protection system. The perceptual hash fingerprint
constitutes technical evidence of copyright registration prior
to the infringing upload.
""".strip()

    # Save evidence file
    evidence_path = Path(EVIDENCE_DIR) / f"{det_id}_takedown.txt"
    evidence_path.write_text(letter)

    # Update DB
    conn = get_conn()
    conn.execute("""
        UPDATE detections
        SET takedown_sent=1, status='takedown_sent',
            evidence_path=?
        WHERE detection_id=?
    """, (str(evidence_path), detection_id))
    conn.commit()
    conn.close()

    return {
        "letter":        letter,
        "platform":      plat_info["name"],
        "send_to":       plat_info["email"],
        "form_url":      plat_info["url"],
        "process":       plat_info["process"],
        "response_days": plat_info["response_days"],
        "evidence_path": str(evidence_path),
    }


def get_email_subject(platform: str, label: str) -> str:
    """Generate email subject line for takedown."""
    return f"DMCA Takedown Notice — Unauthorised Use of Copyrighted Image: {label}"


def get_supported_platforms() -> list:
    return list(PLATFORM_CONTACTS.keys())
