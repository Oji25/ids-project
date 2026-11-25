import json
import pathlib
import subprocess

HOME = pathlib.Path.home()
RUNNER = HOME / "executorch/cmake-out/examples/models/llama/llama_main"
MODEL = HOME / "executorch/llama32_1b_8da4w_ctx128.pte"
TOKENIZER = HOME / "models/llama32-1b/original/tokenizer.model"

template = open("prompts/net_explain_v1.txt").read()
lines = open("results/evidence.jsonl").read().splitlines()

N = 3
for i, line in enumerate(lines[:N]):
    obj=json.loads(line)
    evidence = (
        f"Device {obj['source_device']} was flagged as {obj['verdict']}."
        f"The alert type is {obj['alert_type']}."
    )
    prompt = template.replace("{EVIDENCE}", evidence)
    result = subprocess.run(
        [str(RUNNER), f"--model_path={MODEL}", f"--tokenizer_path={TOKENIZER}","--seq_len=512",
         f"--prompt={prompt}", "--temperature=0", "--max_new_tokens=24"],
        capture_output=True, text=True)
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
