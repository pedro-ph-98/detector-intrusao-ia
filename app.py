import streamlit as st
import pandas as pd
import joblib
import numpy as np


st.set_page_config(page_title="CyberShield Pro", page_icon="🛡️", layout="wide")

#CSS  terminal/painel de segurança
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
        background-color: #ff4b4b;
        color: white;
        font-weight: bold;
    }
    .metric-card {
        background-color: #1a1c24;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #ff4b4b;
    }
    </style>
    """, unsafe_allow_html=True)

@st.cache_resource
def load_assets():
    model = joblib.load('modelo_cyber_final.pkl')
    le_attack = joblib.load('label_encoder.pkl')
    return model, le_attack

model, le_attack = load_assets()

# --- HEADER ---
st.title("🛡️ CyberShield AI: IDS v2.0")
st.markdown("---")

# --- LAYOUT EM COLUNAS ---
col_input, col_display = st.columns([1, 2], gap="large")

with col_input:
    st.subheader("📡 Monitoramento de Fluxo")
    with st.container():
        src_port = st.number_input("Porta de Origem", 0, 65535, 443)
        dst_port = st.number_input("Porta de Destino", 0, 65535, 80)
        protocol = st.select_slider("Severidade do Protocolo", options=[1, 6, 17], value=6, help="1: ICMP, 6: TCP, 17: UDP")
        
        bytes_sent = st.number_input("Bytes Enviados", min_value=0, step=100)
        bytes_received = st.number_input("Bytes Recebidos", min_value=0, step=100)
        
        is_internal = st.toggle("Conexão Interna/VPN", value=False)
        
        btn_analisar = st.button("EXECUTAR SCAN")

with col_display:
    st.subheader("📊 Relatório de Análise")
    
    if btn_analisar:
        # Lógica de processamento
        total_bytes = bytes_sent + bytes_received
        input_df = pd.DataFrame([[
            src_port, dst_port, protocol, bytes_sent, 
            bytes_received, total_bytes, 1 if is_internal else 0
        ]], columns=['src_port', 'dst_port', 'protocol', 'bytes_sent', 'bytes_received', 'total_bytes', 'is_internal_traffic'])
        
        # Predição e Probabilidade 
        prediction = model.predict(input_df)[0]
        probs = model.predict_proba(input_df)[0]
        result_name = le_attack.inverse_transform([prediction])[0]
        confidence = np.max(probs) * 100

        # Exibição de Métricas
        m1, m2 = st.columns(2)
        with m1:
            st.metric("Status da Ameaça", result_name.upper(), delta="ALERTA" if result_name != 'benign' else "LIMPO", delta_color="inverse")
        with m2:
            st.metric("Confiança da IA", f"{confidence:.2f}%")

        # Feedback Visual
        if result_name == 'benign':
            st.success(f"**Análise Concluída:** Nenhum padrão malicioso detectado no fluxo atual.")
            st.info("O tráfego segue os padrões normais de comportamento da rede.")
        else:
            st.error(f"**Atenção:** Padrão compatível com {result_name.upper()} detectado.")
            st.progress(int(confidence), text="Nível de Risco")
            
            # Recomendações de Segurança
            with st.expander("🛡️ Próximos Passos Sugeridos"):
                st.write(f"1. Bloquear IP de origem na porta {src_port}.")
                st.write(f"2. Isolar o host de destino ({dst_port}) para análise de logs.")
                st.write(f"3. Verificar assinatura de payload para {result_name}.")

    else:
        st.info("Aguardando entrada de dados para iniciar o monitoramento...")

# --- FOOTER ---
st.markdown("---")
st.caption("Desenvolvido para o Projeto de IA - Curso de ADS 2026")