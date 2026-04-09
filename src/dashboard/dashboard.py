import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import time

# --- CONFIGURATION DE LA PAGE (Crucial pour le style) ---
st.set_page_config(
    page_title="SATELLITE GROUND CONTROL",
    page_icon="🛰️",
    layout="wide", # Utilise toute la largeur
    initial_sidebar_state="collapsed"
)

# --- CSS PERSONNALISÉ (Le cœur du design Satellite/Dark) ---
# Nous injectons du CSS pour modifier l'apparence par défaut de Streamlit
st.markdown("""
<style>
    /* Import de polices Monospace style 'code/terminal' */
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        background-color: #050509; /* Fond presque noir */
        color: #e0e0e0;
        font-family: 'Share Tech Mono', monospace;
    }

    /* Personnalisation des titres */
    h1, h2, h3 {
        color: #00f2fe !important; /* Bleu cyan néon */
        text-transform: uppercase;
        letter-spacing: 2px;
        border-bottom: 1px solid #00f2fe;
        padding-bottom: 10px;
    }

    /* Style des conteneurs 'Cartes' (Cards) */
    div[data-testid="stVerticalBlock"] > div:has(div.stMarkdown) {
        # background-color: #0a0e17;
        # border: 1px solid #1f293a;
        # border-radius: 5px;
        # padding: 15px;
    }
    
    /* Ciblage spécifique des colonnes pour faire des cartes */
    [data-testid="column"] {
        background-color: #0d111a; /* Fond des cartes légèrement plus clair */
        border: 1px solid #1f3a5f; /* Bordure bleue sombre */
        border-radius: 4px;
        padding: 20px;
        box-shadow: 0 0 10px rgba(0, 242, 254, 0.1); /* Lueur subtile */
    }

    /* Style des Métriques */
    [data-testid="stMetricValue"] {
        color: #4df2a8 !important; /* Vert fluo pour les valeurs */
        font-size: 2.5rem !important;
    }
    [data-testid="stMetricLabel"] {
        color: #a0a0a0 !important;
        text-transform: uppercase;
    }

    /* Personnalisation des boutons */
    .stButton>button {
        background-color: transparent;
        color: #00f2fe;
        border: 2px solid #00f2fe;
        border-radius: 0px;
        text-transform: uppercase;
        width: 100%;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        background-color: #00f2fe;
        color: #050509;
        box-shadow: 0 0 15px rgba(0, 242, 254, 0.5);
    }

    /* Barre de progression */
    .stProgress > div > div > div > div {
        background-color: #00f2fe;
    }
    
    /* Masquer le menu Streamlit par défaut pour plus d'immersion */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {background: rgba(0,0,0,0);}

</style>
""", unsafe_allow_html=True)

# --- GÉNÉRATION DE DONNÉES SIMULÉES (Pour la démo) ---
def get_satellite_data():
    # Simulation d'un statut
    status = np.random.choice(["NOMINAL", "ACTIVE", "RE-CALIBRATING"], p=[0.7, 0.2, 0.1])
    # Simulation de coordonnées au-dessus de la France
    lat = 48.8566 + np.random.normal(0, 2)
    lon = 2.3522 + np.random.normal(0, 3)
    # Données d'analyse (ex: couverture nuageuse simulée)
    df_metrics = pd.DataFrame({
        'Timestamp': pd.date_range(start='now', periods=10, freq='min'),
        'Signal_Strength': np.random.uniform(80, 100, 10),
        'Data_Accuracy': np.random.uniform(0.95, 0.99, 10)
    })
    return status, lat, lon, df_metrics

# --- MISE EN PAGE DU DASHBOARD ---

# 1. EN-TÊTE (Header)
st.markdown("# 🛰️ SENTINEL-X1 / GROUND CONTROL INTERFACE")
st.markdown(f"**Current System Time (UTC):** `{time.strftime('%Y-%m-%d %H:%M:%S')}`")
st.write("---")

# Simulation de chargement des résultats (optionnel)
with st.spinner('📡 INCOMING DATA STREAM...'):
    time.sleep(1) 
    status, lat, lon, df = get_satellite_data()


# 2. ZONE PRINCIPALE (Grille de résultats)
col1, col2 = st.columns([1, 2]) # Col 1 plus étroite que Col 2

with col1:
    st.markdown("### 📡 SYSTEM STATUS")
    
    # Indicateur de statut avec couleur conditionnelle en HTML
    color = "#4df2a8" if status == "NOMINAL" else "#ff4b4b"
    st.markdown(f"""
    <div style="background-color: #1a1f2c; padding: 10px; border-radius: 5px; border-left: 5px solid {color}; margin-bottom: 20px;">
        <span style="color: #a0a0a0;">ORBITAL STATUS:</span><br>
        <span style="color: {color}; font-size: 25px; font-weight: bold;">{status}</span>
    </div>
    """, unsafe_allow_html=True)

    # Métriques Clés
    m1, m2 = st.columns(2)
    m1.metric(label="Lat", value=f"{lat:.2f}°N")
    m2.metric(label="Lon", value=f"{lon:.2f}°E")
    
    m3, m4 = st.columns(2)
    m3.metric(label="Alt", value="705 km", delta="-0.2 km")
    m4.metric(label="Temp", value="-25°C", delta="2°C")

    st.write("---")
    st.markdown("### ⚙️ ACTIONS")
    st.button("REQUEST NEW IMAGE ACQUISITION")
    st.button("PERFORM SENSOR CALIBRATION")

with col2:
    st.markdown("### 🗺️ TARGET AREA MAPPING")
    
    # Création d'une carte Plotty Express style sombre/satellite
    # On simule un point cible
    map_data = pd.DataFrame({'lat': [lat], 'lon': [lon], 'info': ['Target Alpha']})
    
    fig_map = px.scatter_mapbox(map_data, lat="lat", lon="lon", zoom=4, 
                                 mapbox_style="carto-darkmatter") # Style de carte sombre
    
    fig_map.update_traces(marker=dict(size=15, color='#00f2fe', symbol='circle'))
    
    # Layout noir pour s'intégrer au design
    fig_map.update_layout(
        margin={"r":0,"t":0,"l":0,"b":0},
        paper_bgcolor="#0d111a",
        plot_bgcolor="#0d111a",
        font_color="#e0e0e0"
    )
    st.plotly_chart(fig_map, use_container_width=True)

st.write("---")

# 3. ZONE INFÉRIEURE (Graphiques temporels)
st.markdown("### 📊 TELEMETRY ANALYSIS")

c1, c2 = st.columns(2)

with c1:
    # Graphique Force du Signal
    fig_signal = px.line(df, x='Timestamp', y='Signal_Strength', title='SIGNAL STRENGTH (dB)')
    fig_signal.update_traces(line_color='#00f2fe') # Bleu néon
    fig_signal.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e0e0e0",
        xaxis=dict(showgrid=False), yaxis=dict(showgrid=True, gridcolor='#1f293a')
    )
    st.plotly_chart(fig_signal, use_container_width=True)

with c2:
    # Graphique Précision
    fig_acc = px.area(df, x='Timestamp', y='Data_Accuracy', title='DATA ACCURACY RATIO')
    fig_acc.update_traces(line_color='#4df2a8', fillcolor='rgba(77, 242, 168, 0.2)') # Vert néon
    fig_acc.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e0e0e0",
        xaxis=dict(showgrid=False), yaxis=dict(showgrid=True, gridcolor='#1f293a')
    )
    st.plotly_chart(fig_acc, use_container_width=True)


# 4. FOOTER (Console log)
st.markdown("### 🖥️ SYSTEM LOG")
st.code("""
[INFO] - 10:32:01 - Receiving telemetry packet 8842...
[INFO] - 10:32:05 - Image sensor powered up.
[WARN] - 10:32:10 - Minor jitter detected in reaction wheel 2.
[INFO] - 10:32:15 - Data stream visualization updated.
""", language='bash')