import streamlit as st
import pandas as pd
import joblib
import numpy as np

# Configuração da página
st.set_page_config(page_title="CyberShield ADS", page_icon="🛡️")

@st.cache_resource
def load_model():
    # Carrega o modelo otimizado e o encoder de nomes
    model = joblib.load('modelo_cyber_final.pkl')
    le_attack = joblib.load('label_encoder.pkl')
    return model, le_attack

try:
    model, le_attack = load_model()
except:
    st.error("Erro ao carregar os arquivos .pkl. Certifique-se de que estão na mesma pasta.")

st.title("🛡️ Sistema Inteligente de Detecção de Intrusão")
st.write("Esta aplicação utiliza **XGBoost** para identificar ameaças em tráfego de rede.")

with st.sidebar:
    st.header("Configurações da Conexão")
    src_port = st.number_input("Porta de Origem", 0, 65535, 443)
    dst_port = st.number_input("Porta de Destino", 0, 65535, 80)
    protocol = st.selectbox("Protocolo", [6, 17, 1], format_func=lambda x: {6:"TCP", 17:"UDP", 1:"ICMP"}[x])
    
st.subheader("Dados do Tráfego")
col1, col2 = st.columns(2)
with col1:
    bytes_sent = st.number_input("Bytes Enviados", min_value=0, value=100)
with col2:
    bytes_received = st.number_input("Bytes Recebidos", min_value=0, value=100)

is_internal = st.toggle("Tráfego Interno", value=False)

if st.button("Analisar Ameaça", use_container_width=True):
    # Engenharia de atributos em tempo real
    total_bytes = bytes_sent + bytes_received
    
    # Criar DataFrame com as colunas EXATAS do treino
    input_df = pd.DataFrame([[
        src_port, dst_port, protocol, bytes_sent, 
        bytes_received, total_bytes, 1 if is_internal else 0
    ]], columns=['src_port', 'dst_port', 'protocol', 'bytes_sent', 'bytes_received', 'total_bytes', 'is_internal_traffic'])
    
    # Predição
    prediction = model.predict(input_df)[0]
    result_name = le_attack.inverse_transform([prediction])[0]
    
    # Interface de Resultado
    st.divider()
    if result_name == 'benign':
        st.balloons()
        st.success(f"### ✅ Resultado: Tráfego Seguro ({result_name})")
    else:
        st.warning(f"### 🚨 ALERTA: Ameaça Detectada!")
        st.error(f"Tipo de Ataque: **{result_name.upper()}**")