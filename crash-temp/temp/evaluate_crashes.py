# -*- coding: utf-8 -*-
"""
evaluate_crashes.py
===================
Evaluation script for comparative crash analysis across all seed-generation methods.

Supported methods:
  - EvoLFuzzer (Ours)   → fuzz_test_evolfuzzer.jsonl
  - Random (RMA)        → fuzz_test_rma.jsonl
  - ACO                 → fuzz_test_aco.jsonl
  - EA                   → fuzz_test_ea.jsonl
  - GA                   → fuzz_test_ga.jsonl
  - PSO                  → fuzz_test_pso.jsonl

Usage:
    python evaluate_crashes.py

Workflow (per method):
    1. Read seed/fuzz_test_{method}.jsonl
    2. Call execute_test_case for every input in that file
    3. Crashes are saved to crashes_{method}/  (deduplicated by crash ID)
    4. Print a comparative table for all methods.

Crash deduplication: handled entirely by fuzz_programmer_test.save_crash_locally
(file existence check), guaranteeing identical crash detection for every method.
"""

import glob
import json
import os
import sys
from collections import Counter
from decimal import Decimal

from tqdm import tqdm

# Ensure 'crash' is treated as a package so relative imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crash.fuzz_programmer_test import execute_test_case, reliability_guard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def convert_to_float(obj):
    """递归将 Decimal 转换为 float"""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {key: convert_to_float(value) for key, value in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_float(item) for item in obj]
    return obj


def load_jsonl(path):
    """加载 .jsonl 文件"""
    records = []
    if not os.path.exists(path):
        print("[WARN] 文件不存在: {}".format(path))
        return records
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def count_crashes_in_folder(folder):
    """
    统计文件夹中唯一的 .json 文件数量（即唯一崩溃数），
    并返回按异常类型分类的 Counter。
    """
    pattern = os.path.join(folder, "*.json")
    files = glob.glob(pattern)
    type_counter = Counter()
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            exc_type = data.get("info", {}).get("type", "Unknown")
            type_counter[exc_type] += 1
        except Exception:
            type_counter["ParseError"] += 1
    return len(files), type_counter


# ---------------------------------------------------------------------------
# Patched save_crash_locally — routes crashes to a caller-specified folder
# ---------------------------------------------------------------------------

def _patched_save_crash_locally(crash_info, test_input, output_dir):
    """将崩溃写入 output_dir，而非默认的 detected_crashes/"""
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, "{}_{}.json".format(crash_info['type'], crash_info['id'][:8]))
    if not os.path.exists(filename):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({"info": crash_info, "input": test_input}, f, indent=4)


def run_evaluation_for_method(jsonl_path, output_folder, method_label):
    """
    读取 jsonl_path，对每条记录调用 execute_test_case，
    将崩溃写入 output_folder，返回统计摘要。
    """
    # 每次评估前清空旧结果（确保干净对比）
    if os.path.exists(output_folder):
        for old_file in glob.glob(os.path.join(output_folder, "*.json")):
            os.remove(old_file)
    else:
        os.makedirs(output_folder, exist_ok=True)

    # 动态 patch fuzz_programmer_test.save_crash_locally
    import crash.fuzz_programmer_test as ft_module
    _original_save = ft_module.save_crash_locally
    ft_module.save_crash_locally = lambda info, inp: _patched_save_crash_locally(info, inp, output_folder)

    records = load_jsonl(jsonl_path)
    print("\n[{}] 共加载 {} 条记录，崩溃输出目录: {}/".format(method_label, len(records), output_folder))

    total_inputs = 0
    total_crashes = 0

    for record in tqdm(records, desc="  {}".format(method_label), unit="record"):
        code = record.get("code", "")
        cwe_id = record.get("ID", "unknown")
        fuzzing_inputs = record.get("fuzzing_inputs", [])

        if not fuzzing_inputs or not isinstance(fuzzing_inputs, list):
            continue

        for test_input in fuzzing_inputs:
            if not isinstance(test_input, dict):
                continue
            total_inputs += 1
            try:
                test_input_converted = convert_to_float(test_input)
                execute_test_case(code, test_input_converted)
            except Exception:
                pass  # execute_test_case 内部已捕获异常，不影响后续

    # 恢复原始函数
    ft_module.save_crash_locally = _original_save

    crash_count, type_counter = count_crashes_in_folder(output_folder)
    return {
        "method": method_label,
        "total_inputs": total_inputs,
        "unique_crashes": crash_count,
        "type_counter": type_counter,
    }


def print_comparison_table(results):
    """打印对比表格"""
    print("\n" + "=" * 80)
    print("  表 1: 安全指标 — Unique Crashes 对比 ")
    print("=" * 80)
    header = "  {:<20} {:>15} {:>18} {:<35}".format("Method", "Total Inputs", "Unique Crashes", "Top Exception Types")
    print(header)
    print("  " + "-" * 92)
    for r in results:
        top_types = ", ".join("{}".format(t) for t, c in r["type_counter"].most_common(3))
        if not top_types:
            top_types = "N/A"
        row = "  {:<20} {:>15} {:>18} {:<35}".format(
            r['method'], r['total_inputs'], r['unique_crashes'], top_types
        )
        print(row)
    print("=" * 92)
    print()

    # 汇总行：找 EvoLFuzzer ( Ours ) 与其他方法的差值
    evo = next((r for r in results if "EvoLFuzzer" in r["method"]), None)
    others = [r for r in results if "EvoLFuzzer" not in r["method"]]
    if evo:
        for other in others:
            delta = evo["unique_crashes"] - other["unique_crashes"]
            sign = "+" if delta > 0 else ""
            print("  → EvoLFuzzer vs {}: {} vs {}  差值: {}{}".format(
                other['method'], evo['unique_crashes'], other['unique_crashes'], sign, delta
            ))
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    reliability_guard(maximum_memory_bytes=2 ** 32)

    # seed/ 和崩溃输出目录都放在 crash/ 下，与种子生成脚本保持一致
    crash_dir = os.path.dirname(os.path.abspath(__file__))
    seed_dir = os.path.join(crash_dir, "seed")

    configs = [
        {
            "jsonl": os.path.join(seed_dir, "fuzz_test_evolfuzzer.jsonl"),
            "output_folder": os.path.join(crash_dir, "humaneval/crashes_evolfuzzer"),
            "method_label": "EvoLFuzzer (Ours)",
        },
        {
            "jsonl": os.path.join(seed_dir, "fuzz_test_rma.jsonl"),
            "output_folder": os.path.join(crash_dir, "humaneval/crashes_random"),
            "method_label": "Random (RMA)",
        },
        {
            "jsonl": os.path.join(seed_dir, "fuzz_test_aco.jsonl"),
            "output_folder": os.path.join(crash_dir, "humaneval/crashes_aco"),
            "method_label": "ACO",
        },
        {
            "jsonl": os.path.join(seed_dir, "fuzz_test_ea.jsonl"),
            "output_folder": os.path.join(crash_dir, "humaneval/crashes_ea"),
            "method_label": "EA",
        },
        {
            "jsonl": os.path.join(seed_dir, "fuzz_test_ga.jsonl"),
            "output_folder": os.path.join(crash_dir, "humaneval/crashes_ga"),
            "method_label": "GA",
        },
        {
            "jsonl": os.path.join(seed_dir, "fuzz_test_pso.jsonl"),
            "output_folder": os.path.join(crash_dir, "humaneval/crashes_pso"),
            "method_label": "PSO",
        },
    ]

    results = []
    for cfg in configs:
        result = run_evaluation_for_method(
            jsonl_path=cfg["jsonl"],
            output_folder=cfg["output_folder"],
            method_label=cfg["method_label"],
        )
        results.append(result)

    print_comparison_table(results)

    print("各方法崩溃文件保存路径：")
    for cfg in configs:
        abs_path = os.path.abspath(cfg["output_folder"])
        crash_count, _ = count_crashes_in_folder(cfg["output_folder"])
        print("  [{}] {}  ({} 个唯一崩溃)".format(
            cfg['method_label'], abs_path, crash_count
        ))


if __name__ == "__main__":
    main()
