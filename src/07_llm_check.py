import json
import pathlib
import subprocess

HOME = pathlib.Path.home()
RUNNER = HOME / "executorch/cmake-out/examples/models/llama/llama_main"
MODEL = HOME / "models/llama32-1b/llama.pte"
TOKENIZER = HOME / "models/llama32-1b/tokenizer.json"

template = open("prompts/net_explain_v1.txt").read()
lines = open("results/evidence.jsonl").read().splitlines()

N = 3
for i, line in enumerate(lines[:N]):
    obj=json.loads(line)

    evidence = (
        f"Device: {obj['source_device']}. "
        f"Verdict: {obj['verdict']}. "
        f"Alert: {obj['alert_type']}. "
        f"Within {obj['window_seconds']} seconds: "
        f"{obj['flows_in_window']} network connections (flows), "
        f"{obj['unique_destination_ports']} different ports, "
        f"{obj['unique_destination_ips']} destination IPs, "
        f"{obj['packets_per_second']} packets per second. "
        f"Classifier score: {obj['classifier_score']}. "
        f"Anomaly score: {obj['anomaly_score']}."
    )
    prompt = template.replace("{EVIDENCE}", evidence)
    result = subprocess.run(
        [str(RUNNER), f"--model_path={MODEL}", f"--tokenizer_path={TOKENIZER}","--seq_len=512",
         f"--prompt={prompt}", "--temperature=0", "--max_new_tokens=100"],
        capture_output=True, text=True, check=True)
    llm_output = result.stdout
    llm_output = llm_output.split("PyTorchObserver")[0]
    generated = llm_output.replace(prompt, "").strip()
    generated = generated.split("<|eot_id|>")[0]
    generated = generated.split("In one short sentence")[0]
    generated = generated.split("In\n")[0]
    generated = generated.strip()
    device = obj["source_device"]

    final_message = f"""
    Alert for {device}

    Risk:
    {generated}

    Actions:
    1. Check the device for unusual activity.
    2. Review router/firewall logs.
    """
    open(f"results/llm_example_{i}.txt", "w").write(final_message)
    print(f"Saved llm_example_{i}.txt")
