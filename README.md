# EdgeSentinel
Offline network-security advisory prototype | Bharat AI-SoC Challenge 2026–27

## Scope
The repository contains a CIC-IDS2017-derived detection pipeline, trained specialist models and recorded alert evidence. The Streamlit console replays 300 recorded alerts and runs fresh Llama inference locally. It does not perform live packet capture. Remediation guidance is predefined; detector calibration and Raspberry Pi validation remain pending.

## Run on the development Mac
Python 3.11, Apple Silicon ARM64, Streamlit, a compatible ExecuTorch `llama_main`, Llama 3.2 1B SpinQuant XNNPACK `.pte` and its tokenizer are required.

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install streamlit pandas numpy scikit-learn pyarrow joblib
export ET_RUNNER="$HOME/executorch/cmake-out/examples/models/llama/llama_main"
export ET_MODEL="$HOME/models/llama32-1b/llama.pte"
export ET_TOKENIZER="$HOME/models/llama32-1b/tokenizer.json"
python -m streamlit run app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

Model: https://huggingface.co/software-mansion/Llama-3.2-ExecuTorch (1b/xnnpack/llama_3_2_1b_xnnpack_spinquant.pte). Obtain compatible tokenizer and comply with model license. Runtime source: https://github.com/pytorch/executorch ; development commit `0ce7106831`. Build CPU preset, configure XNNPACK as needed, install libraries, then build standalone `examples/models/llama` target `llama_main`. Model and runtime are not bundled here. Do not commit weights or virtual environments.

## Initial measured result
One ARM64 inference smoke test: 68.38 prompt tokens/s, 40.02 decode tokens/s, 234 ms first-token latency excluding model load, 4.42 s model load, 2.708 s inference. No Pi or power benchmark claimed.

## Limitations
Detector false positives need calibration; LLM text may hallucinate or truncate. No verified live capture, phishing/SMS detection or Pi deployment. Recorded evidence is explicitly labeled in the application. 
