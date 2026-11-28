"""Compare how published-report claims reach an offline reviewer."""

import argparse
import json
from pathlib import Path
import random
import re
from time import perf_counter


SEEDS = (11, 23, 37, 53)
BUDGET = 4
CLAIM_FLAGS = ("所有", "均", "证明", "全程", "完整", "无需", "确认", "更省", "节省")


def offline_ranker(weights):
    from fwmap.agent.llm import _patch_torch

    torch = _patch_torch()
    from transformers import AutoModelForCausalLM, AutoTokenizer

    device = "cuda" if torch.cuda.is_available() else "cpu"
    tokenizer = AutoTokenizer.from_pretrained(weights, local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(weights, local_files_only=True, dtype="auto")
    model.to(device).eval()

    def rank(cards):
        content = (
            "你在复核论文的陈述。将下面所有条目按需要修订或补证的优先级从高到低排列。"
            "只依据相应归档摘要，看看陈述是否得到足够支持。输出严格的 JSON 字符串数组，"
            "元素只能是各条 ID，每个 ID 出现一次。不要输出解释。\n"
            + json.dumps(cards, ensure_ascii=False)
        )
        prompt = tokenizer.apply_chat_template(
            [{"role": "user", "content": content}], tokenize=False, add_generation_prompt=True
        )
        inputs = tokenizer(prompt, return_tensors="pt", add_special_tokens=False).to(device)
        with torch.inference_mode():
            output = model.generate(
                **inputs, max_new_tokens=128, do_sample=False, pad_token_id=tokenizer.eos_token_id
            )
        return tokenizer.decode(output[0, inputs.input_ids.shape[1]:], skip_special_tokens=True).strip()

    return rank, device


def evaluate(order, flagged):
    first = next(i for i, card_id in enumerate(order, start=1) if card_id in flagged)
    return {"first_review": first, "review_in_first_four": len(flagged.intersection(order[:BUDGET]))}


def run(data, rank):
    cards = [{key: card[key] for key in ("id", "claim", "archive")} for card in data["cases"]]
    expected_ids = {card["id"] for card in cards}
    flagged = set(data["needs_review"])
    if len(expected_ids) != len(cards) or not flagged or not flagged <= expected_ids:
        raise ValueError("missing, invalid or duplicate case IDs")

    rounds = []
    for seed in SEEDS:
        shuffled = random.Random(seed).sample(cards, len(cards))
        fixed = [card["id"] for card in shuffled]
        rules = sorted(shuffled, key=lambda card: -sum(word in card["claim"] for word in CLAIM_FLAGS))
        rules_order = [card["id"] for card in rules]
        start = perf_counter()
        reply = rank(shuffled)
        elapsed = round(perf_counter() - start, 3)
        fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", reply, flags=re.DOTALL | re.IGNORECASE)
        try:
            model_order = json.loads(fenced.group(1) if fenced else reply)
        except json.JSONDecodeError:
            model_order = None
        valid = (
            isinstance(model_order, list)
            and len(model_order) == len(expected_ids)
            and all(isinstance(card_id, str) for card_id in model_order)
            and set(model_order) == expected_ids
        )
        rounds.append({
            "seed": seed,
            "fixed": {"order": fixed, **evaluate(fixed, flagged)},
            "rules": {"order": rules_order, **evaluate(rules_order, flagged)},
            "model": (
                {"order": model_order, **evaluate(model_order, flagged)}
                if valid else {"invalid_reply": reply}
            ),
            "model_strict_valid": valid and fenced is None,
            "model_seconds": elapsed,
        })
    return rounds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("weights", type=Path, help="local model directory")
    args = parser.parse_args()
    data = json.loads(Path(__file__).with_suffix(".json").read_text(encoding="utf-8"))
    rank, device = offline_ranker(args.weights)
    result = {"device": device, "budget": BUDGET, "rounds": run(data, rank)}
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
