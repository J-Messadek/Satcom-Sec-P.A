"""Console de debug façon VS Code, intégrée au dashboard.

Capture les logs applicatifs réels (actions utilisateur, résultats du pipeline,
erreurs) via le module `logging` standard et les affiche dans un panneau
togglable au style terminal sombre. Le buffer est rattaché au thread courant
(`threading.local`) plutôt qu'au logger lui-même : comme Streamlit exécute
chaque session utilisateur dans son propre thread de script, deux sessions
concurrentes ne se mélangent jamais dans la même console.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from html import escape

import streamlit as st
import streamlit.components.v1 as components

LOGGER_NAME = "satcom.dashboard"
MAX_LINES = 300

_local = threading.local()

_LEVEL_COLORS = {
    "DEBUG": "#6a9955",
    "INFO": "#9cdcfe",
    "WARNING": "#dcdcaa",
    "ERROR": "#f14c4c",
    "CRITICAL": "#f14c4c",
}


class _SessionBufferHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        buffer = getattr(_local, "buffer", None)
        if buffer is None:
            return
        buffer.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": record.levelname,
            "message": record.getMessage(),
        })
        del buffer[:-MAX_LINES]


def init_console() -> logging.Logger:
    """À appeler en tête de chaque rerun du script Streamlit.

    Crée le buffer de logs de la session (persistant via st.session_state) et
    l'attache au thread courant pour que les logs émis pendant ce run
    atterrissent dans la bonne console."""
    st.session_state.setdefault("console_logs", [])
    _local.buffer = st.session_state["console_logs"]

    logger = logging.getLogger(LOGGER_NAME)
    if not any(isinstance(h, _SessionBufferHandler) for h in logger.handlers):
        logger.addHandler(_SessionBufferHandler())
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger


def clear_console() -> None:
    st.session_state["console_logs"] = []


def render_console(height: int = 260) -> None:
    logs = st.session_state.get("console_logs", [])

    if not logs:
        body = '<div class="line dim">// aucun evenement pour le moment — utilise le dashboard</div>'
    else:
        body = "".join(
            f'<div class="line">'
            f'<span class="time">{entry["time"]}</span>'
            f'<span class="level" style="color:{_LEVEL_COLORS.get(entry["level"], "#d4d4d4")}">'
            f'{entry["level"]:<8}</span>'
            f'<span class="msg">{escape(entry["message"])}</span>'
            f'</div>'
            for entry in logs
        )

    html = f"""
    <div class="term">
      <div class="term-bar">
        <span class="dot red"></span><span class="dot yellow"></span><span class="dot green"></span>
        <span class="term-title">DEBUG CONSOLE — satcom.dashboard ({len(logs)})</span>
      </div>
      <div class="term-body" id="term-body">{body}</div>
    </div>
    <style>
      * {{ box-sizing: border-box; }}
      .term {{ font-family: 'Cascadia Code', Consolas, 'Courier New', monospace;
               background: #1e1e1e; border-radius: 6px; overflow: hidden;
               border: 1px solid #333; }}
      .term-bar {{ background: #323233; padding: 6px 10px; display: flex;
                   align-items: center; gap: 6px; }}
      .dot {{ width: 11px; height: 11px; border-radius: 50%; display: inline-block; }}
      .red {{ background: #ff5f56; }}
      .yellow {{ background: #ffbd2e; }}
      .green {{ background: #27c93f; }}
      .term-title {{ color: #ccc; font-size: 12px; margin-left: 8px; }}
      .term-body {{ padding: 8px 12px; height: {max(height - 38, 60)}px;
                    overflow-y: auto; font-size: 12.5px; }}
      .line {{ white-space: pre-wrap; word-break: break-word; padding: 1px 0; color: #d4d4d4; }}
      .line.dim {{ color: #6a737d; font-style: italic; }}
      .time {{ color: #6a737d; margin-right: 8px; }}
      .level {{ display: inline-block; width: 70px; font-weight: bold; margin-right: 8px; }}
    </style>
    <script>
      var el = document.getElementById('term-body');
      if (el) {{ el.scrollTop = el.scrollHeight; }}
    </script>
    """
    components.html(html, height=height, scrolling=False)


def render_console_toggle() -> None:
    """Bloc sidebar (checkbox + bouton clear) + rendu de la console si activée."""
    with st.sidebar:
        st.markdown("### 🖥️ Debug")
        show = st.checkbox("Afficher la console", key="show_console")
        if show and st.button("🧹 Vider la console"):
            clear_console()

    if st.session_state.get("show_console"):
        st.write("---")
        render_console()
