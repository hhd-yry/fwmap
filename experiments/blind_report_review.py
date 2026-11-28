"""Measure report review order with a local, order-blinded model reviewer."""

import argparse
import json
from pathlib import Path
import random
from time import perf_counter

from experiments.report_claim_review import BUDGET, CLAIM_FLAGS, offline_generator


SESSIONS = (
    ("K4", "X", "original"),
    ("M7", "Y", "rules"),
    ("R3", "Y", "original"),
    ("T8", "X", "rules"),
)
SEEDS = {"X": 101, "Y": 202}
PROMPT = (
    "你是论文事实复核者。只按归档摘要判断。陈述的每项内容都得到支持时，回答 OK。"
    "陈述错误、超出摘要范围，或证据不足时，回答 REVIEW。只输出一个英文标签，不解释。"
)


def orders(sets):
    arranged = {}
    for name, cases in sets.items():
        original = random.Random(SEEDS[name]).sample(cases, len(cases))
        rules = sorted(original, key=lambda card: -sum(word in card["claim"] for word in CLAIM_FLAGS))
        arranged[name] = {"original": original, "rules": rules}
    return arranged


def review(sets, generate):
    arranged = orders(sets)
    sessions = {}
    generate(PROMPT + "\n陈述：目录包含五条记录。\n归档摘要：目录条目数为五。", 12)
    for blind_id, name, method in SESSIONS:
        observations = []
        for case in arranged[name][method]:
            prompt = f"{PROMPT}\n陈述：{case['claim']}\n归档摘要：{case['archive']}"
            start = perf_counter()
            reply = generate(prompt, 12)
            observations.append({
                "id": case["id"],
                "reply": reply,
                "seconds": round(perf_counter() - start, 4),
            })
        sessions[blind_id] = observations
    return sessions


def score(sets, labels, sessions):
    arranged = orders(sets)
    scores = []
    for blind_id, name, method in SESSIONS:
        observations = sessions[blind_id]
        ids = [item["id"] for item in observations]
        expected = [case["id"] for case in arranged[name][method]]
        if ids != expected:
            raise ValueError(f"unexpected item order in archived session {blind_id}")
        predictions = [item["reply"].strip().upper() for item in observations]
        positives = labels.intersection(ids)
        flagged = [card_id for card_id, response in zip(ids, predictions) if response == "REVIEW"]
        top = set(ids[:BUDGET])
        caught = positives.intersection(flagged)
        first = next((i for i, card_id in enumerate(ids, 1) if card_id in caught), None)
        scores.append({
            "session": blind_id,
            "set": name,
            "ordering": method,
            "first_correct": first,
            "seconds_to_first_correct": (
                round(sum(item["seconds"] for item in observations[:first]), 4)
                if first is not None else None
            ),
            "correct_in_budget": len(caught & top),
            "missed_in_budget": len(positives - (caught & top)),
            "false_flags_in_budget": len((set(flagged) - positives) & top),
            "all_correct_flags": len(caught),
            "all_missed": len(positives - caught),
            "all_false_flags": len(set(flagged) - positives),
            "invalid_replies": sum(response not in {"OK", "REVIEW"} for response in predictions),
        })
    return scores


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--weights", type=Path, help="local model directory")
    mode.add_argument("--score", type=Path, help="archived blind observations")
    args = parser.parse_args()
    data = json.loads(Path(__file__).with_suffix(".json").read_text(encoding="utf-8"))
    if args.weights is not None:
        generate, device = offline_generator(args.weights)
        result = {"device": device, "sessions": review(data["sets"], generate)}
    else:
        saved = json.loads(args.score.read_text(encoding="utf-8-sig"))
        scores = score(data["sets"], set(data["needs_review"]), saved["sessions"])
        result = {"budget": BUDGET, "scores": scores}
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
