import json, os, platform, re, subprocess, time
from pathlib import Path
import streamlit as st
import pandas as pd

ROOT = Path(__file__).resolve().parent
HOME = Path.home()
RUNNER = Path(os.getenv('ET_RUNNER', str(HOME / 'executorch/cmake-out/examples/models/llama/llama_main')))
MODEL = Path(os.getenv('ET_MODEL', str(HOME / 'models/llama32-1b/llama.pte')))
TOKENIZER = Path(os.getenv('ET_TOKENIZER', str(HOME / 'models/llama32-1b/tokenizer.json')))
st.set_page_config(page_title='EdgeSentinel | Security console', layout='wide', initial_sidebar_state='expanded')
st.markdown('''<style>
.stApp{background:#0b1018;color:#e5edf7} [data-testid=stHeader]{background:#0b1018} [data-testid=stSidebar]{background:#101722;border-right:1px solid #263241} [data-testid=stSidebar] *{color:#d9e4f2} .block-container{padding-top:2.2rem;max-width:1500px;padding-bottom:2rem} h1,h2,h3,p,label{color:#e5edf7} h1{font-size:2rem!important;letter-spacing:-.04em} h2{font-size:1.35rem!important} h3{font-size:1.05rem!important} [data-testid=stMetric]{background:#111c29;border:1px solid #273749;border-radius:9px;padding:12px 15px} [data-testid=stMetricValue]{font-size:1.65rem;color:#67e8d1} [data-testid=stMetricLabel]{color:#a6b9cc} div[data-testid=stVerticalBlockBorderWrapper]{border-color:#283647} .eyebrow{font-size:11px;letter-spacing:2px;color:#6ee7cd;font-weight:700} .brand{font-size:25px;font-weight:800;letter-spacing:-1px;color:#e7f2ff} .muted{color:#8ca2b8;font-size:13px} .status{background:#102a27;color:#79e5c5;border:1px solid #255348;padding:6px 10px;border-radius:6px;font-size:12px;display:inline-block} .stButton button[kind=primary]{background:#087f78;border:0;color:white} hr{border-color:#263241} </style>''',unsafe_allow_html=True)
try:
    alerts=[json.loads(x) for x in (ROOT/'results/evidence.jsonl').read_text().splitlines() if x.strip()]
    if not alerts: raise ValueError('No evidence records')
except Exception as e:
    st.error(f'Cannot load evidence: {e}'); st.stop()
with st.sidebar:
    st.markdown('<div class="eyebrow">EDGE SECURITY / 01</div><div class="brand">EdgeSentinel</div><div class="muted">Security operations console</div>',unsafe_allow_html=True)
    st.divider()
    page=st.radio('WORKSPACE',['Incident investigation','Alert inventory','System & validation'])
    st.divider()
    st.markdown('<span class="status">LOCAL CPU RUNTIME</span>',unsafe_allow_html=True)
    st.caption(f'{platform.machine()} · ExecuTorch · Llama 3.2 1B')
    st.caption('Data source: recorded network evidence. No live packet capture.')
    st.caption('Bharat AI-SoC Challenge 2026–27')
if page=='Alert inventory':
    st.title('Alert inventory')
    st.caption('Recorded detector outputs — not confirmed attacks')
    df=pd.DataFrame(alerts)
    a,b,c=st.columns(3);a.metric('Records',len(df));b.metric('Devices',df.source_device.nunique());c.metric('Alert types',df.alert_type.nunique())
    st.bar_chart(df.alert_type.value_counts(),horizontal=True)
    st.dataframe(df,hide_index=True,use_container_width=True)
    st.stop()
if page=='System & validation':
    st.title('System & validation')
    st.markdown('**Pipeline**  ·  Flow features → ML classifier / anomaly detector / rules → risk fusion → local Llama advisory')
    st.markdown('**Runtime assets**')
    for name,p in [('Runner',RUNNER),('Model',MODEL),('Tokenizer',TOKENIZER)]:
        st.write(f'{name}: '+('Available' if p.is_file() else 'Missing'))
    st.markdown('**Initial measured ARM64 smoke test**')
    a,b,c=st.columns(3);a.metric('Decode','40.02 tok/s');b.metric('First token','234 ms');c.metric('Model load','4.42 s')
    st.caption('Single earlier test; first-token time excludes model loading. Not a Raspberry Pi benchmark.')
    st.markdown('**Validation gaps**')
    st.write('Live capture and Raspberry Pi deployment are pending. Detection thresholds require calibration. LLM explanations can be inaccurate. SMS and phishing detection are outside the current prototype. Power and peak memory have not been measured on this Mac.')
    st.stop()
st.markdown('<div class="eyebrow">OPERATIONS / INCIDENT INVESTIGATION</div>',unsafe_allow_html=True)
st.title('Network threat intelligence')
st.caption('Recorded alerts · Interactive evidence inspection · Fresh on-device AI inference')
a,b,c,d=st.columns(4);a.metric('Recorded alerts',len(alerts));b.metric('Devices',len({x['source_device'] for x in alerts}));c.metric('Architecture',platform.machine());d.metric('Runtime','ExecuTorch')
left,right=st.columns([1.05,1])
with left:
    with st.container(border=True):
        st.subheader('01  /  Investigate incident')
        idx=st.selectbox('Select recorded alert',range(len(alerts)),index=min(1,len(alerts)-1),format_func=lambda i:f"{i+1:03d} · {alerts[i]['source_device']} · {alerts[i]['alert_type']}")
        o=alerts[idx]
        st.markdown(f"**{o['source_device']}** · {o['alert_type']}")
        st.warning('Reported verdict: '+o['verdict']+' — unconfirmed')
        a,b=st.columns(2);a.metric('Network flows',f"{o['flows_in_window']:,}");b.metric('Unique ports',f"{o['unique_destination_ports']:,}")
        a,b=st.columns(2);a.metric('Destinations',o['unique_destination_ips']);b.metric('Window',f"{o['window_seconds']} s")
        st.caption(f"Packet rate: {o['packets_per_second']} /s · SYN ratio: {o['syn_packet_ratio']}")
        st.markdown('**Detector signals**')
        for label,key in [('Classifier','classifier_score'),('Anomaly detector','anomaly_score')]:
            v=float(o[key]);st.caption(f'{label} · {v:.2f}');st.progress(max(0.,min(1.,v)))
        if o['classifier_score']<.2: st.info('Low classifier support; corroboration is needed.')
        with st.expander('Raw evidence'):st.json(o)
with right:
    with st.container(border=True):
        st.subheader('02  /  Local AI advisor')
        st.caption('Llama 3.2 1B · XNNPACK · SpinQuant')
        st.markdown('**Verified observations**')
        st.write(f"{o['flows_in_window']:,} flows across {o['unique_destination_ports']:,} ports and {o['unique_destination_ips']} destinations in {o['window_seconds']} seconds. These observations alone do not confirm an intrusion.")
        if st.button('Run local analysis',type='primary',use_container_width=True):
            st.session_state.pop('advice',None)
            evidence=f"Flows: {o['flows_in_window']}; unique ports: {o['unique_destination_ports']}; destinations: {o['unique_destination_ips']}; duration: {o['window_seconds']} seconds; packet rate: {o['packets_per_second']}."
            prompt=('<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\nExplain network observations cautiously. No citations, no invented facts, no confirmed attacks. Do not infer transferred data volume or successful logins. Answer in one short sentence.<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n'+evidence+' What should a user investigate?<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n')
            try:
                with st.spinner('Running on this device…'):
                    t=time.perf_counter();r=subprocess.run([str(RUNNER),f'--model_path={MODEL}',f'--tokenizer_path={TOKENIZER}',f'--prompt={prompt}','--seq_len=512','--max_new_tokens=80','--temperature=0'],capture_output=True,text=True,check=True,timeout=120);elapsed=time.perf_counter()-t
                raw=r.stdout.split('PyTorchObserver')[0].replace(prompt,'').split('<|eot_id|>')[0].split('<|end_of_text|>')[0].strip()
                sentences=re.findall(r'[^.!?]+[.!?](?=\s|$)',raw)
                text=sentences[0].strip() if sentences else raw
                m=re.search(r'PyTorchObserver\s+(\{[^\n]+\})',r.stdout+'\n'+r.stderr);stats=json.loads(m.group(1)) if m else {}
                st.session_state['advice']={'idx':idx,'text':text,'stats':stats,'elapsed':elapsed}
            except Exception as e:st.error(f'Inference failed: {e}')
        advice=st.session_state.get('advice');advice=advice if advice and advice['idx']==idx else None
        if advice:
            st.markdown('**Generated interpretation**');st.write(advice['text'] or 'No usable generated text.');st.caption('Unverified AI output; use the original evidence to check its claims.')
            s=advice['stats'];a,b=st.columns(2);a.metric('Total response',f"{advice['elapsed']:.2f} s");b.metric('Decode',f"{s['decode_token_per_sec']:.1f} tok/s" if 'decode_token_per_sec' in s else 'N/A')
            if 'first_token_ms' in s and 'inference_start_ms' in s:st.caption(f"First token: {s['first_token_ms']-s['inference_start_ms']} ms (excludes loading)")
        else:st.caption('Run analysis to generate a fresh advisory on your CPU.')
    with st.container(border=True):
        st.subheader('03  /  Response playbook')
        actions=['Verify whether the activity is expected.','Review router and firewall logs.','Inspect the flagged device for unfamiliar applications.']
        for i,action in enumerate(actions,1):st.write(f'{i:02d}  {action}')
        st.caption('Predefined guidance · No automated blocking')
        st.download_button('Export incident report',json.dumps({'mode':'recorded evidence','evidence':o,'local_ai':advice,'predefined_actions':actions},indent=2),file_name='incident.json',mime='application/json',use_container_width=True)
