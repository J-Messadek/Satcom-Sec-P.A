import sys
from pathlib import Path

import streamlit as st
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.pipeline import ATTACKS, attack_image, defend_image, run_attack_defense

INPUT_DIR = ROOT / "data" / "input"

st.set_page_config(page_title="SatCOM", page_icon="🛰️", layout="wide")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@600;800&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        background: radial-gradient(circle at 20% 0%, #0a1428 0%, #050509 60%);
        color: #d8e0ec;
        font-family: 'Share Tech Mono', monospace;
    }
    h1, h2, h3, h4 { color: #00f2fe !important; letter-spacing: 1px; }
    .satcom-title {
        font-family: 'Orbitron', sans-serif; font-size: 2.6rem; font-weight: 800;
        background: linear-gradient(90deg, #00f2fe, #4df2a8);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        margin-bottom: 0;
    }
    .satcom-sub { color: #7a8aa0; text-transform: uppercase; letter-spacing: 3px; font-size: .8rem; }
    [data-testid="stMetricValue"] { color: #4df2a8 !important; font-size: 1.7rem !important; }
    [data-testid="stMetricLabel"] { color: #8a98ac !important; text-transform: uppercase; }
    [data-testid="stImage"] img { border: 1px solid #1f3a5f; border-radius: 6px; }
    .stButton>button {
        background: transparent; color: #00f2fe; border: 1.5px solid #00f2fe;
        border-radius: 4px; text-transform: uppercase; width: 100%; font-weight: bold;
        transition: all .25s;
    }
    .stButton>button:hover { background: #00f2fe; color: #050509; box-shadow: 0 0 18px rgba(0,242,254,.5); }
    #MainMenu, footer { visibility: hidden; }
    [data-testid="stSidebar"] { background: #070b14; border-right: 1px solid #142540; }
</style>
""", unsafe_allow_html=True)


def list_input_images() -> list[str]:
    if not INPUT_DIR.exists():
        return []
    return sorted(p.name for p in INPUT_DIR.iterdir() if p.is_file())


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


def pixels_to_image(data: bytes, size) -> Image.Image:
    need = size[0] * size[1] * 3
    return Image.frombytes("RGB", size, data[:need].ljust(need, b"\x00"))


st.markdown('<p class="satcom-title">🛰️ SatCOM</p>', unsafe_allow_html=True)
st.markdown('<p class="satcom-sub">Chaîne de communication satellite · attaque & résilience</p>',
            unsafe_allow_html=True)
st.write("")

with st.sidebar:
    st.markdown("### 📡 Source")
    images = list_input_images()
    name = st.selectbox("Image", images) if images else None
    uploaded = st.file_uploader("…ou téléverser", type=["png", "bmp", "jpg", "jpeg"])
    max_px = st.select_slider("Résolution démo", [96, 128, 160, 200, 256], value=160)

    st.markdown("### 🌩️ Canal")
    intensity = st.slider("Intensité du brouillage", 0.0, 1.0, 0.15, 0.01)
    snr_db = st.slider("SNR (dB)", 0.0, 30.0, 8.0, 0.5)
    mode = st.selectbox("Mode", ["barrage", "pulse", "tone", "multi"])
    seed = st.number_input("Seed", value=2026, step=1)

    st.markdown("### 🛡️ Reed-Solomon")
    ecc_symbols = st.slider("Symboles ECC", 2, 64, 32, 2)

image = load_image(name, uploaded, max_px)

tab_img, tab_frame = st.tabs(["🛰️ LIAISON IMAGE", "🔐 AUTHENTIFICATION DES TRAMES"])

# ---------------------------------------------------------------------------
# Liaison image : attaque (brouillage) puis défense (Reed-Solomon)
# ---------------------------------------------------------------------------
with tab_img:
    if image is None:
        st.info("📥 Sélectionne ou téléverse une image dans la barre latérale.")
    else:
        raw = image.tobytes()
        params = dict(snr_db=snr_db, intensity=intensity, mode=mode, seed=int(seed))

        _, b_atk, b_def, _ = st.columns(4)
        if b_atk.button("🛑 Lancer l'attaque"):
            res = attack_image(raw, **params)
            st.session_state["attack"] = (pixels_to_image(res.output, image.size), res)
            st.session_state.pop("defense", None)
        if b_def.button("🛡️ Activer la défense"):
            with st.spinner("Correction Reed-Solomon…"):
                res = defend_image(raw, ecc_symbols=ecc_symbols, **params)
            st.session_state["defense"] = (pixels_to_image(res.output, image.size), res)

        attack = st.session_state.get("attack")
        defense = st.session_state.get("defense")

        c_src, c_atk, c_def = st.columns(3)
        with c_src:
            st.markdown("#### Source")
            st.image(image, use_container_width=True)
            st.caption(f"{image.size[0]}×{image.size[1]} px")
        with c_atk:
            st.markdown("#### 🛑 Sous attaque")
            if attack is None:
                st.caption("Clique sur « Lancer l'attaque ».")
            else:
                img_a, res_a = attack
                st.image(img_a, use_container_width=True)
                st.caption(f"{res_a.byte_errors} octets corrompus · {res_a.flipped_bits} bits inversés")
        with c_def:
            st.markdown("#### 🛡️ Avec défense")
            if defense is None:
                st.caption("Clique sur « Activer la défense ».")
            else:
                img_d, res_d = defense
                st.image(img_d, use_container_width=True)
                tag = "image intacte" if res_d.corrected else f"{res_d.byte_errors} octets résiduels"
                st.caption(f"Reed-Solomon ({ecc_symbols} ECC) · {tag}")

        if attack is not None:
            st.write("---")
            res_a = attack[1]
            integ_a = 100 * (1 - res_a.byte_error_rate)
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Intégrité sans défense", f"{integ_a:.1f}%")
            m2.metric("Bits inversés", f"{res_a.flipped_bits}")
            if defense is not None:
                res_d = defense[1]
                integ_d = max(0.0, 100 * (1 - res_d.byte_error_rate))
                m3.metric("Intégrité avec défense", f"{integ_d:.1f}%", f"{integ_d - integ_a:+.1f} pts")
                m4.metric("Verdict", "✅ RÉCUPÉRÉE" if res_d.corrected else "⚠️ AU-DELÀ DU RS")
            else:
                m3.metric("Intégrité avec défense", "—")
                m4.metric("Verdict", "—")

# ---------------------------------------------------------------------------
# Authentification des trames : altération de header vs HMAC + IDS
# ---------------------------------------------------------------------------
with tab_frame:
    st.markdown("Un attaquant altère une trame et **reforge le CRC**. "
                "Le récepteur le détecte via l'**IDS structurel** et l'**authentification HMAC**.")

    f1, f2, f3 = st.columns(3)
    n_packets = f1.slider("Nombre de trames", 3, 20, 8)
    apid = f2.number_input("APID attendu", value=0x42, step=1)
    attack_kind = f3.selectbox("Attaque", list(ATTACKS), format_func=ATTACKS.get)

    target = st.slider("Trame ciblée (seqCount)", 0, n_packets - 1, min(1, n_packets - 1))

    if st.button("🛑 Lancer l'attaque sur les trames"):
        st.session_state["frame"] = run_attack_defense(
            attack_kind, num_packets=n_packets, apid=int(apid), target_seq=int(target),
            insert_after=max(target - 1, 0))

    res = st.session_state.get("frame")
    if res is None:
        st.caption("Configure puis lance une attaque pour voir le verdict de la défense.")
    else:
        st.write("---")
        v1, v2 = st.columns(2)
        v1.error("🔓 CRC trompé — l'attaquant a reforgé le CRC." if res.crc_still_valid
                 else "CRC : altération non masquée.")
        v2.error("🚨 Attaque détectée par l'IDS / HMAC." if not res.all_valid
                 else "🛡️ Trafic authentique.")

        d1, d2, d3 = st.columns(3)
        d1.metric("Trames authentifiées", f"{res.verified_count}/{res.num_packets}")
        d2.metric("Alertes IDS", len(res.structural_alerts))
        d3.metric("Alertes HMAC", len(res.hmac_alerts))

        for title, alerts in [("🔎 IDS structurel", res.structural_alerts),
                              ("🔐 Authentification HMAC", res.hmac_alerts)]:
            if alerts:
                with st.expander(title, expanded=True):
                    for a in alerts:
                        st.markdown(f"- **{a['type']}** (seq {a['seqCount']}) — {a['detail']}")
