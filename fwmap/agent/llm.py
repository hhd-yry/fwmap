"""本地 LLM 封装：4-bit 量化加载 + 强制 JSON 输出 + 失败重试。

为什么不用 AutoTokenizer：transformers 5.x 里 Qwen2 的慢速 tokenizer 有 bug
（`vocab` and `merges` must be both be from memory or both filenames），
所以这里统一走 tokenizer.json + PreTrainedTokenizerFast。
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys
import time

# agent 依赖（torch / transformers / bitsandbytes / accelerate）通常不在系统 Python 里，
# 而是单独装一份。以前要用户自己设 PYTHONPATH，忘了就静默失败；这里按顺序自己找。
#
# 顺序：环境变量 → 包旁边的 tools\pylibs → 开发机上那份。
# 最后一项是历史遗留路径，只在本机存在时生效 —— 换台机器不会因为它而失败。
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for _cand in (os.environ.get("FWMAP_AGENT_LIBS"),
              os.path.join(_PKG_ROOT, "tools", "pylibs"),
              r"C:\deepseek\libs-bnb"):
    if _cand and os.path.isdir(_cand) and _cand not in sys.path:
        sys.path.insert(0, _cand)

# 默认模型路径按包目录算，不写死盘符：便携包里把模型放 tools\models\ 就能被找到。
DEFAULT_MODEL = os.path.join(_PKG_ROOT, "tools", "models", "Qwen2.5-Coder-7B-Instruct")


def find_model(model_path: str | None = None, verbose: bool = False) -> str:
    """按优先级找模型：参数 → FWMAP_LLM_MODEL → 默认位置 → 包旁边/常见缓存里的 Qwen*。"""
    import glob as _glob
    cands: list[str] = []
    if model_path:
        cands.append(model_path)
    env = os.environ.get("FWMAP_LLM_MODEL")
    if env:
        cands.append(env)
    cands.append(DEFAULT_MODEL)
    pkg_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for base in (os.path.join(pkg_root, "tools", "models"),
                 os.path.join(os.path.dirname(pkg_root), "tools", "models"),
                 os.path.expanduser("~/.cache/huggingface/hub")):
        try:
            cands.extend(sorted(_glob.glob(os.path.join(base, "*Qwen*"))))
        except Exception:
            pass
    for c in cands:
        if c and os.path.isdir(c):
            return c
    if verbose:
        print("[!] 没找到本地模型，试过：")
        for c in cands:
            print("      " + str(c))
        print("    请设置 FWMAP_LLM_MODEL 指向模型目录（需含 config.json 与 *.safetensors）。")
    return cands[0] if cands else DEFAULT_MODEL
_MODEL = None
_TOK = None


def _patch_torch():
    import torch
    # 这台机器的 transformers 5.x 比 torch 2.6 新，缺一个 fp8 常量
    if not hasattr(torch, "float8_e8m0fnu"):
        torch.float8_e8m0fnu = torch.float8_e4m3fn
    return torch


def _load_tokenizer(path: str):
    from transformers import AutoTokenizer
    try:
        return AutoTokenizer.from_pretrained(path, use_fast=True)
    except Exception:                                    # noqa: BLE001
        from transformers import PreTrainedTokenizerFast
        cfg_path = os.path.join(path, "tokenizer_config.json")
        cfg = {}
        if os.path.exists(cfg_path):
            cfg = json.load(open(cfg_path, encoding="utf-8"))
        tok = PreTrainedTokenizerFast(
            tokenizer_file=os.path.join(path, "tokenizer.json"),
            eos_token=cfg.get("eos_token"), pad_token=cfg.get("pad_token") or cfg.get("eos_token"),
            unk_token=cfg.get("unk_token"))
        if cfg.get("chat_template"):
            tok.chat_template = cfg["chat_template"]
        return tok


def model_size_gb(path: str) -> float:
    """模型权重有多大（GB）。没有权重文件返回 0。"""
    total = 0
    for pat in ("*.safetensors", "*.bin"):
        for f in glob.glob(os.path.join(path, pat)):
            try:
                total += os.path.getsize(f)
            except OSError:
                pass
    return total / (1 << 30)


def free_ram_gb() -> float:
    """当前可用物理内存。查不到就返回 0（当作"不知道"，不要让检查变成误报）。"""
    try:
        if os.name == "nt":
            import ctypes

            class _MemStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            st = _MemStatus()
            st.dwLength = ctypes.sizeof(st)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
            return st.ullAvailPhys / (1 << 30)
        with open("/proc/meminfo", encoding="ascii", errors="replace") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / (1 << 20)
    except Exception:                                   # noqa: BLE001
        pass
    return 0.0


def fit_model(path: str) -> tuple[bool, str, str]:
    """这个模型装得下吗？返回 (能不能装, 说明, 同目录里更小的替代)。

    判断标准（实测过 7B 在 8 GB 显卡上能跑）：
    - **显存**是硬门槛：4-bit 大约占 size/4 + 1 GB，装不进就是装不进；
    - **内存**只是"偏紧"：加载时是流式读 safetensors，不需要把 14 GB 全驻留。
      内存紧张时可能偶发访问违例（退出码 3221225477），但**不该拦着不让试** ——
      拦掉一个本来能跑的模型，比偶尔崩一次更糟。
    """
    if not path or not os.path.isdir(path):
        return False, f"模型目录不存在：{path}", ""
    size = model_size_gb(path)
    if size <= 0:
        return False, f"{os.path.basename(path)} 里没有权重文件（*.safetensors / *.bin）", ""

    need_vram = size / 4 + 1.0
    total_vram = 0.0
    try:
        import torch

        if torch.cuda.is_available():
            total_vram = torch.cuda.get_device_properties(0).total_memory / (1 << 30)
    except Exception:                                   # noqa: BLE001
        pass

    if total_vram and need_vram > total_vram * 0.95:
        alt = _smaller_sibling(path, budget=(total_vram * 0.95 - 1.0) * 4)
        return False, (f"{os.path.basename(path)} 4-bit 需要约 {need_vram:.1f} GB 显存，"
                       f"这台只有 {total_vram:.1f} GB"), alt

    free = free_ram_gb()
    if free and size > free * 4:
        alt = _smaller_sibling(path, budget=free * 4)
        return False, (f"{os.path.basename(path)} 有 {size:.1f} GB，当前只有 {free:.1f} GB 内存可用，"
                       f"差得太远"), alt
    if free and size > free * 1.5:
        return True, (f"{os.path.basename(path)}（{size:.1f} GB）内存偏紧"
                      f"（可用 {free:.1f} GB），加载时如果崩了就重试一次或先关掉别的程序"), ""
    return True, f"{os.path.basename(path)}（{size:.1f} GB，显存约需 {need_vram:.1f} GB）", ""


def _smaller_sibling(path: str, budget: float) -> str:
    """同目录里找一个装得下的（优先最大的那个装得下的）。"""
    parent = os.path.dirname(os.path.abspath(path))
    best, best_size = "", 0.0
    try:
        for name in os.listdir(parent):
            p = os.path.join(parent, name)
            if p == os.path.abspath(path) or not os.path.isdir(p):
                continue
            s = model_size_gb(p)
            if 0 < s <= budget and s > best_size:
                best, best_size = p, s
    except OSError:
        pass
    return best


def load(model_path: str | None = None):
    """懒加载（全局只加载一次）。"""
    global _MODEL, _TOK
    if _MODEL is not None:
        return _MODEL, _TOK
    torch = _patch_torch()
    from transformers import AutoModelForCausalLM, BitsAndBytesConfig

    path = find_model(model_path)
    ok, why, alt = fit_model(path)
    if not ok:
        if alt:
            print(f"[llm] {why}", flush=True)
            print(f"[llm] 改用同目录里装得下的：{os.path.basename(alt)}", flush=True)
            path = alt
        else:
            raise RuntimeError(f"{why}。换小一点的模型，或者不加 --llm/--agent 只跑规则。")
    elif why:
        print(f"[llm] {why}", flush=True)
    t0 = time.time()
    _TOK = _load_tokenizer(path)
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.float16,
                             bnb_4bit_use_double_quant=True)
    _MODEL = AutoModelForCausalLM.from_pretrained(
        path, quantization_config=bnb, dtype=torch.float16, low_cpu_mem_usage=True)
    _MODEL.to("cuda")
    _MODEL.eval()
    vram = torch.cuda.memory_allocated() / 1e9
    print(f"[llm] {os.path.basename(path)} loaded in {time.time()-t0:.0f}s, VRAM {vram:.2f} GB",
          flush=True)
    return _MODEL, _TOK


def endpoint() -> str:
    """远程模型服务地址（OpenAI 兼容）。设了它就不在本进程里加载模型。

    为什么要有这个：虚拟机里跑不了大模型 —— VMware 是虚拟显卡、没有 CUDA，
    8 GB 内存也装不下 7B。但宿主机有 4060。让宿主起一个 `fwmap serve`，
    VM 里的 triage 用 `FWMAP_LLM_ENDPOINT` 指过去，就能同时要「GPU 模型 + qemu 动态验证」。
    """
    return (os.environ.get("FWMAP_LLM_ENDPOINT") or "").strip().rstrip("/")


def _chat_http(messages: list[dict], max_new_tokens: int, temperature: float) -> str:
    import urllib.request

    payload = json.dumps({
        "model": os.environ.get("FWMAP_LLM_NAME") or "fwmap-local",
        "messages": messages,
        "max_tokens": max_new_tokens,
        "temperature": temperature,
    }).encode("utf-8")
    req = urllib.request.Request(endpoint() + "/chat/completions", payload,
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=1800) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        raise RuntimeError(f"模型服务返回的格式不对：{str(data)[:200]}")


def chat(messages: list[dict], max_new_tokens: int = 320, temperature: float = 0.0,
         model_path: str | None = None) -> str:
    if endpoint():                     # 远程模式：本进程不加载模型
        return _chat_http(messages, max_new_tokens, temperature)
    model, tok = load(model_path)
    torch = _patch_torch()
    text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    ids = tok([text], return_tensors="pt").to("cuda")
    kw = dict(max_new_tokens=max_new_tokens, pad_token_id=tok.eos_token_id)
    if temperature > 0:
        kw.update(do_sample=True, temperature=temperature, top_p=0.9)
    else:
        kw.update(do_sample=False)
    with torch.no_grad():
        gen = model.generate(**ids, **kw)
    return tok.decode(gen[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)


def json_object(text: str) -> dict | None:
    """从模型回复里抠出第一个完整 JSON 对象（模型经常带前后废话）。"""
    i = text.find("{")
    while i >= 0:
        depth = 0
        for j in range(i, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[i:j + 1])
                    except json.JSONDecodeError:
                        break
        i = text.find("{", i + 1)
    return None


def ask_json(messages: list[dict], schema_keys: list[str], tries: int = 3,
             max_new_tokens: int = 320) -> tuple[dict | None, str]:
    """要求模型输出 JSON；缺字段/解析失败就带着错误重问。返回 (obj, 原始回复)。"""
    msgs = list(messages)
    last = ""
    for _ in range(tries):
        reply = chat(msgs, max_new_tokens=max_new_tokens)
        last = reply
        obj = json_object(reply)
        if obj is not None:
            missing = [k for k in schema_keys if k not in obj]
            if not missing:
                return obj, reply
            msgs = list(messages) + [
                {"role": "assistant", "content": reply},
                {"role": "user",
                 "content": "Your JSON is missing these keys: " + ", ".join(missing)
                            + ". Reply with the complete JSON object only."},
            ]
        else:
            msgs = list(messages) + [
                {"role": "assistant", "content": reply},
                {"role": "user",
                 "content": "That was not valid JSON. Reply with ONE json object only, "
                            "no explanation, no markdown fence."},
            ]
    return None, last
