Offline IDS with ExecuTorch and Llama 3.2
Overview
This project detects suspicious network activity and generates local security advisories using Llama 3.2 running through ExecuTorch.

Technologies
Python
ExecuTorch
Llama-3.2-1B-Instruct
CICIDS2017
Architecture
Network Traffic -> Feature Extraction -> Intrusion Detection -> Evidence Generation -> ExecuTorch -> Llama 3.2 -> Security Advisory

Hardware
Apple Silicon (ARM64) deployment target

Run
python src/07_llm_check.py
