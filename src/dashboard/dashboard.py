import io
import sys
from pathlib import Path

import streamlit as st
from PIL import Image, ImageFile

ImageFile.LOAD_TRUNCATED_IMAGES = True  # afficher une image JPEG même partiellement corrompue

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.pipeline import ATTACK_INFO, attack_image, defend_image, run_attack_defense

INPUT_DIR = ROOT / "data" / "input"

st.set_page_config(page_title="SatCOM", page_icon="🛰️", layout="wide")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@600;800&display=swap');
    html, body, [data-testid="stAppViewContainer"] {
        background: radial-gradient(circle at 20% 0%, #0a1428 0%, #050509 60%);
        color: #d8e0ec; font-family: 'Share Tech Mono', monospace;
    }
    h1, h2, h3, h4 { color: #00f2fe !important; letter-spacing: 1px; }
    .satcom-title {
        font-family: 'Orbitron', sans-serif; font-size: 2.6rem; font-weight: 800;
        background: linear-gradient(90deg, #00f2fe, #4df2a8);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 0;
    }
    .satcom-sub { color: #7a8aa0; text-transform: uppercase; letter-spacing: 3px; font-size: .8rem; }
    [data-testid="stMetricValue"] { color: #4df2a8 !important; font-size: 1.5rem !important; }
    [data-testid="stMetricLabel"] { color: #8a98ac !important; text-transform: uppercase; }
    [data-testid="stImage"] img { border: 1px solid #1f3a5f; border-radius: 6px; }
    .stButton>button {
        background: transparent; color: #00f2fe; border: 1.5px solid #00f2fe;
        border-radius: 4px; text-transform: uppercase; width: 100%; font-weight: bold; transition: all .25s;
    }
    .stButton>button:hover { background: #00f2fe; color: #050509; box-shadow: 0 0 18px rgba(0,242,254,.5); }
    .card { background:#0b1220; border:1px solid #1f3a5f; border-radius:8px; padding:14px 18px; }
    .card i { color:#7a8aa0; }
    #MainMenu, footer { visibility: hidden; }
    [data-testid="stSidebar"] { background: #070b14; border-right: 1px solid #142540; }
</style>
""", unsafe_allow_html=True)


def list_input_images() -> list[str]:
    return sorted(p.name for p in INPUT_DIR.iterdir() if p.is_file()) if INPUT_DIR.exists() else []


def load_image(name, uploaded, max_px) -> Image.Image | None:
    if uploaded is not None:
        img = Image.open(uploaded)
    elif name is not None:
        img = Image.open(INPUT_DIR / name)
    else:
        return None
    img = img.convert("RGB")
    img.thumbnail((max_px, max_px))
    return img


def to_jpeg(img: Image.Image, quality: int) -> bytes:
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def from_jpeg(data: bytes) -> Image.Image | None:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        return img
    except Exception:
        return None


def from_pixels(data: bytes, size) -> Image.Image:
    need = size[0] * size[1] * 3
    return Image.frombytes("RGB", size, data[:need].ljust(need, b"\x00"))


FRAME_FIELDS = {
    "apid": "APID (identité source)",
    "seqCount": "N° de séquence",
    "seqFlags": "Indicateur (flags)",
    "payload": "Payload (8 1ers octets)",
    "crc": "CRC",
}


def frame_table(before: dict | None, after: dict | None) -> str:
    rows = ["| Champ | 🟢 Trame normale | 🔴 Trame attaquée |", "|---|---|---|"]
    for key, label in FRAME_FIELDS.items():
        b = before[key] if before else "—"
        a = after[key] if after else "—"
        changed = before and after and b != a
        rows.append(f"| {label} | {b} | {'**' + str(a) + '** ⚠️' if changed else a} |")
    return "\n".join(rows)


st.markdown('<p class="satcom-title">🛰️ SatCOM</p>', unsafe_allow_html=True)
st.markdown('<p class="satcom-sub">Chaîne de communication satellite · du bruit à la résilience</p>',
            unsafe_allow_html=True)
st.write("")

with st.sidebar:
    st.markdown("### 📷 Image")
    images = list_input_images()
    name = st.selectbox("Source", images) if images else None
    uploaded = st.file_uploader("…ou téléverser", type=["png", "bmp", "jpg", "jpeg"])
    resolution = st.select_slider("Résolution d'acquisition", [256, 384, 512, 720], value=384)

    st.markdown("### 🗜️ Compression")
    quality = st.slider("Qualité JPEG", 10, 95, 75, 5)

    st.markdown("### 🌩️ Canal")
    intensity = st.slider("Intensité du brouillage", 0.0, 1.0, 0.15, 0.01)
    snr_db = st.slider("SNR (dB)", 0.0, 30.0, 8.0, 0.5)
    mode = st.selectbox("Mode", ["barrage", "pulse", "tone", "multi"])
    seed = st.number_input("Seed", value=2026, step=1)

    st.markdown("### 🛡️ Reed-Solomon")
    ecc_symbols = st.slider("Symboles ECC", 2, 64, 32, 2)

image = load_image(name, uploaded, resolution)
tab_link, tab_frame = st.tabs(["🛰️ CHAÎNE SATELLITE", "🔐 ATTAQUES SUR LES TRAMES"])

# ---------------------------------------------------------------------------
# Onglet 1 : déroulé complet d'une liaison satellite
# ---------------------------------------------------------------------------
with tab_link:
    if image is None:
        st.info("📥 Sélectionne ou téléverse une image dans la barre latérale.")
    else:
        jpeg = to_jpeg(image, quality)
        raw_px = image.size[0] * image.size[1] * 3
        ratio = raw_px / max(len(jpeg), 1)
        params = dict(snr_db=snr_db, intensity=intensity, mode=mode, seed=int(seed))

        if st.button("📡 Lancer la liaison (downlink)"):
            with st.spinner("Transmission + correction Reed-Solomon…"):
                jpg_atk = attack_image(jpeg, **params)
                jpg_dfn = defend_image(jpeg, ecc_symbols=ecc_symbols, **params)

                # Pipeline non compressé illustré en basse résolution (sinon trop lent).
                raw_img = image.copy()
                raw_img.thumbnail((160, 160))
                raw = raw_img.tobytes()
                raw_atk = attack_image(raw, **params)
                raw_dfn = defend_image(raw, ecc_symbols=ecc_symbols, **params)

            st.session_state["link"] = {
                "jpeg_len": len(jpeg), "ratio": ratio, "raw_px": raw_px,
                "jpg_atk": jpg_atk, "jpg_dfn": jpg_dfn,
                "jpg_src": from_jpeg(jpeg),
                "jpg_atk_img": from_jpeg(jpg_atk.output),
                "jpg_dfn_img": from_jpeg(jpg_dfn.output),
                "raw_src": raw_img,
                "raw_atk_img": from_pixels(raw_atk.output, raw_img.size),
                "raw_dfn_img": from_pixels(raw_dfn.output, raw_img.size),
                "raw_dfn": raw_dfn,
            }

        link = st.session_state.get("link")

        st.markdown("##### Déroulé de la liaison")
        s = st.columns(6)
        s[0].metric("📷 Acquisition", f"{image.size[0]}×{image.size[1]}", f"{raw_px // 1024} Ko bruts")
        s[1].metric("🗜️ Compression", f"{len(jpeg) // 1024} Ko", f"ratio {ratio:.0f}:1")
        if link:
            s[2].metric("📡 Downlink", f"{link['jpg_atk'].flipped_bits} bits", "brouillés")
            s[3].metric("🛡️ Reed-Solomon", f"{ecc_symbols} ECC", link["jpg_dfn"].status)
            s[4].metric("📥 Décompression", "OK" if link["jpg_dfn_img"] else "échec")
            s[5].metric("🖼️ Réception", "intacte" if link["jpg_dfn"].corrected
                        else f"{max(100 * (1 - link['jpg_dfn'].byte_error_rate), 0):.0f}%")
        else:
            for i, lbl in [(2, "📡 Downlink"), (3, "🛡️ Reed-Solomon"),
                           (4, "📥 Décompression"), (5, "🖼️ Réception")]:
                s[i].metric(lbl, "—")

        if not link:
            st.write("---")
            st.caption("Clique sur « Lancer la liaison » pour transmettre l'image.")
        else:
            def show(col, title, img, caption, lost_msg):
                with col:
                    st.markdown(title)
                    if img is not None:
                        st.image(img, use_container_width=True)
                        st.caption(caption)
                    else:
                        st.error(lost_msg)

            st.write("---")
            st.markdown("### 🗜️ Transmission compressée (JPEG)")
            a, b, c = st.columns(3)
            show(a, "#### Émise (compressée)", link["jpg_src"],
                 f"{link['jpeg_len'] // 1024} Ko · ratio {ratio:.0f}:1 · artefacts de compression", "")
            show(b, "#### Reçue — sans protection", link["jpg_atk_img"],
                 f"{link['jpg_atk'].flipped_bits} bits perdus dans le flux compressé",
                 "❌ Image perdue : flux compressé trop corrompu pour être décodé.")
            show(c, "#### Reçue — avec Reed-Solomon", link["jpg_dfn_img"],
                 "Erreurs corrigées : image intacte." if link["jpg_dfn"].corrected
                 else f"{link['jpg_dfn'].byte_errors} octets résiduels",
                 "❌ Bruit au-delà de la capacité du code.")

            st.markdown("### 🖼️ Transmission non compressée (pixels bruts)")
            d, e, f = st.columns(3)
            show(d, "#### Émise (source)", link["raw_src"], "image brute, sans compression", "")
            show(e, "#### Reçue — sans protection", link["raw_atk_img"],
                 "bruit réparti sur les pixels (dégradation progressive)", "")
            show(f, "#### Reçue — avec Reed-Solomon", link["raw_dfn_img"],
                 "image intacte : erreurs corrigées." if link["raw_dfn"].corrected
                 else f"{link['raw_dfn'].byte_errors} octets résiduels", "")

            st.info("💡 **Compressée** : un fichier JPEG est compact (ratio élevé) mais **fragile** — "
                    "quelques bits perdus peuvent rendre l'image illisible. **Non compressée** : "
                    "robuste (le bruit ne fait que salir des pixels) mais **bien plus lourde à transmettre**. "
                    "Le **Reed-Solomon** corrige les erreurs dans les deux cas : c'est ce compromis "
                    "compression + codage canal qu'utilise un vrai satellite.")

# ---------------------------------------------------------------------------
# Onglet 2 : attaques sur les trames, expliquées simplement
# ---------------------------------------------------------------------------
with tab_frame:
    st.markdown("Un attaquant intercepte le flux et **modifie une trame**, puis **recalcule le CRC** "
                "pour masquer sa falsification. On observe ce qu'il fait, puis comment la défense réagit.")

    f1, f2 = st.columns([2, 1])
    attack_kind = f1.selectbox("Type d'attaque", list(ATTACK_INFO),
                               format_func=lambda k: f"{ATTACK_INFO[k]['emoji']} {ATTACK_INFO[k]['label']}")
    n_packets = f2.slider("Nombre de trames", 3, 20, 8)

    info = ATTACK_INFO[attack_kind]
    st.markdown(f"<div class='card'><b>{info['emoji']} {info['label']}</b><br>{info['effet']}<br>"
                f"<i>🔁 {info['analogie']}</i></div>", unsafe_allow_html=True)
    st.write("")

    apid = 0x42
    target = st.slider("Trame ciblée (n°)", 0, n_packets - 1, min(1, n_packets - 1))

    changes = {
        "alter_apid": f"Identité de la trame {target} : `APID {apid:#x}` → `APID 0x7ff`",
        "alter_seq_count": f"Numéro d'ordre de la trame {target} : `{target}` → `99`",
        "fuzz_payload": f"Contenu de la trame {target} : plusieurs octets réécrits",
        "fuzz_header": f"En-tête de la trame {target} : tous les champs randomisés",
        "inject_packet": f"Une trame fantôme est insérée après la trame {target}",
    }
    st.caption(f"Ce qui va changer → {changes[attack_kind]}")

    if st.button("▶️ Simuler l'attaque"):
        st.session_state["frame"] = run_attack_defense(
            attack_kind, num_packets=n_packets, apid=apid, target_seq=int(target),
            insert_after=int(target))

    res = st.session_state.get("frame")
    if res is None:
        st.caption("Lance la simulation pour voir le résultat.")
    else:
        st.write("---")
        st.markdown("### 🛑 Simulation de l'attaque (sans protection)")
        st.caption("Comment l'attaque transforme une trame : à gauche une trame normale, "
                   "à droite la trame falsifiée. Les champs modifiés sont marqués ⚠️.")
        st.markdown(frame_table(res.frame_before, res.frame_after), unsafe_allow_html=False)
        st.error("🔓 **CRC recalculé** → la trame falsifiée passe la vérification CRC. "
                 "Sans défense, le récepteur l'accepterait comme légitime.")

        st.write("")
        st.markdown("### 🛡️ Réponse de la défense (avec protection)")
        if res.all_valid:
            st.success("Trafic authentique — aucune anomalie détectée.")
        else:
            st.success("**Attaque détectée et rejetée.** La signature secrète (HMAC) ne correspond "
                       "plus, et/ou l'IDS repère une incohérence de structure.")
        d1, d2, d3 = st.columns(3)
        d1.metric("Trames authentifiées", f"{res.verified_count}/{res.num_packets}")
        d2.metric("Anomalies IDS", len(res.structural_alerts))
        d3.metric("Échecs HMAC", len(res.hmac_alerts))

        for title, alerts in [("🔎 Détail IDS (cohérence des trames)", res.structural_alerts),
                              ("🔐 Détail HMAC (authenticité)", res.hmac_alerts)]:
            if alerts:
                with st.expander(title):
                    for a in alerts:
                        st.markdown(f"- **{a['type']}** (trame {a['seqCount']}) — {a['detail']}")

        st.write("")
        st.markdown("### 📋 Journal des événements")
        st.code("\n".join(res.events), language=None)
