"""本地 LLM 封装：4-bit 量化加载 + 强制 JSON 输出 + 失败重试。

为什么不用 AutoTokenizer：transformers 5.x 里 Qwen2 的慢速 tokenizer 有 bug
（`vocab` and `merges` must be both be from memory or both filenames），
所以这里统一走 tokenizer.json + PreTrainedTokenizerFast。
"""

from __future__ import annotations

import json
import os
import re
import sys
import time

# agent 依赖（torch / transformers / bitsandbytes / accelerate）装在独立目录里。
# 以前要用户自己设 PYTHONPATH，忘了就静默失败；这里自动加进 sys.path。
_LIBS = os.environ.get("FWMAP_AGENT_LIBS") or r"C:\deepseek\libs-bnb"
if os.path.isdir(_LIBS) and _LIBS not in sys.path:
    sys.path.insert(0, _LIBS)

DEFAULT_MODEL = r"C:\deepseek\tools\models\Qwen2.5-Coder-7B-Instruct"


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


def load(model_path: str | None = None):
    """懒加载（全局只加载一次）。"""
    global _MODEL, _TOK
    if _MODEL is not None:
        return _MODEL, _TOK
    torch = _patch_torch()
    from transformers import AutoModelForCausalLM, BitsAndBytesConfig

    path = find_model(model_path)
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


def chat(messages: list[dict], max_new_tokens: int = 320, temperature: float = 0.0,
         model_path: str | None = None) -> str:
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
