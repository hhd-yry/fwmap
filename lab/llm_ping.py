import json
import urllib.request

op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    r = op.open("http://127.0.0.1:11434/v1/models", timeout=15)
    print("MODELS:", r.read().decode()[:200])
    req = urllib.request.Request(
        "http://127.0.0.1:11434/v1/chat/completions",
        data=json.dumps({"messages": [{"role": "user", "content": "hi"}],
                         "max_tokens": 8}).encode(),
        headers={"Content-Type": "application/json"})
    print("CHAT:", op.open(req, timeout=180).read().decode()[:300])
except Exception as e:
    print("ERR:", type(e).__name__, e)
