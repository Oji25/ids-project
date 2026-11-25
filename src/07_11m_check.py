import json
import pathlib
import subprocess

HOME = pathlib.Path.home()
RUNNER = HOME / "executorch/cmake-out/examples/models/llama/llama_main"
MODEL = HOME / "executorch/llama32_1b_8da4w.pte"
TOKENIZER = HOME / "models/llama32-1b/original/tokenizer.model"

template = open("prompts/net_explain_v1.txt").read()
lines = open("results/evidence.jsonl").read().splitlines()

N = 3
for i, line in enumerate(lines[:N]):
    obj=json.loads(line)
    evidence=json.dumps({
        "verdict": obj["verdict"],
        "alert_type": obj["alert_type"],
        "source_device": obj["source_device"]
    })
    prompt = template.replace("{EVIDENCE}", evidence)
    print("Prompt length:",len(prompt))
    print(prompt[:300])
    result = subprocess.run(
        [str(RUNNER), f"--model_path={MODEL}", f"--tokenizer_path={TOKENIZER}",
         f"--prompt={prompt}", "--temperature=0", "--seq_len=128"],
        capture_output=True, text=True)
    open(f"results/llm_example_{i}.txt", "w").write(result.stdout)
    print(f"\n===== example {i} =====")
    print(result.stdout[-1500:] if result.stdout else result.stderr[-1500:])
