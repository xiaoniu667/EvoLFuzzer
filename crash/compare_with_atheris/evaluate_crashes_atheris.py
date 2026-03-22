# -*- coding: utf-8 -*-
"""
evaluate_crashes_atheris.py
===========================
在 4 个数据集（HumanEval, MBPP, CWEval, LLM-SecEval）上
对 EvoLFuzzer 和 Atheris 进行公平崩溃检测对比评估。

Reviewer Response: 添加真正的工业级模糊测试器基线 Atheris
(Google SOTA Python Fuzzer)，与 EvoLFuzzer 在统一执行预算下进行对比。

实验设计（控制变量）:
  1. 统一执行预算 (Budget): 所有方法每个任务执行 50 次测试
  2. 路径去重 (Path Deduplication): 只有发现新执行路径的测试用例才会被保存
  3. Atheris 配置: 与 EvoLFuzzer 使用相同的初始种子数量和迭代次数

Supported methods:
  - EvoLFuzzer (Ours)  → 进化算法 + LLM 指导的语义模糊测试
  - Atheris (Google)  → 覆盖率引导的字节级模糊测试（SOTA Python Fuzzer）

Supported datasets:
  - HumanEval     → crash/humaneval/
  - MBPP          → crash/mbpp/
  - CWEval        → crash/cweval/
  - LLM-SecEval   → crash/securityeval/

Usage:
    python evaluate_crashes_atheris.py
"""

import glob
import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import traceback
import uuid
from collections import Counter, defaultdict
from contextlib import contextmanager, redirect_stdout
from decimal import Decimal

import coverage
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fuzz_programmer_test import execute_test_case, reliability_guard


# ---------------------------------------------------------------------------
# 内联崩溃检测（不依赖修改后的 fuzz_programmer_test.py）
# ---------------------------------------------------------------------------

def save_crash_to_folder(crash_info, test_input, output_folder):
    """将崩溃写入指定目录"""
    os.makedirs(output_folder, exist_ok=True)
    filename = os.path.join(output_folder, f"{crash_info['type']}_{crash_info['id'][:8]}.json")
    if not os.path.exists(filename):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({"info": crash_info, "input": test_input}, f, indent=4)


def execute_and_detect_crashes(code, test_input, output_folder):
    """
    执行测试并检测崩溃。
    返回 (coverage_score, is_pass, covered_lines)
    """
    # 导入需要的模块
    import importlib
    import importlib.util

    # 保存到临时文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
        temp_file.write(code)
        temp_file_path = temp_file.name

    cov_data_file = os.path.join(os.path.dirname(temp_file_path), f".coverage_{uuid.uuid4().hex}")
    cov = coverage.Coverage(data_file=cov_data_file, include=[temp_file_path], omit=[])

    coverage_score = 0
    is_pass = False
    covered_lines = set()

    # 超时装饰器
    class TimeoutException(Exception):
        pass

    @contextmanager
    def timeout(seconds):
        def handler(signum, frame):
            raise TimeoutException()
        try:
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(seconds)
            yield
        finally:
            signal.alarm(0)

    # 加载模块
    try:
        spec = importlib.util.spec_from_file_location("temp_module", temp_file_path)
        module = importlib.util.module_from_spec(spec)
        with timeout(3):
            spec.loader.exec_module(module)
    except TimeoutException:
        raise RuntimeError("Code loading timed out")
    except Exception as e:
        raise RuntimeError(f"Failed to load code: {e}")

    # 获取函数
    func_names = [line.split('(')[0].replace('def ', '').strip()
                  for line in code.splitlines() if line.strip().startswith('def')]
    func_name = func_names[0] if func_names else None
    if not func_name:
        raise RuntimeError("No function found in code")
    fuc = getattr(module, func_name)

    try:
        cov.start()
        with timeout(3):
            fuc(**test_input)
        is_pass = True
    except Exception as e:
        is_pass = False
        tb_str = traceback.format_exc()
        # 只记录非超时异常
        if "TimeoutException" not in tb_str:
            crash_id = hashlib.md5(tb_str.encode()).hexdigest()
            crash_info = {
                "type": type(e).__name__,
                "msg": str(e),
                "stack": tb_str,
                "id": crash_id
            }
            save_crash_to_folder(crash_info, test_input, output_folder)
    finally:
        try:
            cov.stop()
            cov.save()
            data = cov.get_data()
            if data and temp_file_path in data.measured_files():
                line_counts = cov._analyze(temp_file_path).numbers
                total_lines = line_counts.n_statements
                missed_lines = line_counts.n_missing
                if total_lines > 0:
                    coverage_score = 100.0 * (total_lines - missed_lines) / total_lines
                covered_lines = set(data.lines(temp_file_path)) if data.lines(temp_file_path) else set()
        except Exception:
            pass
        # 清理临时文件
        try:
            os.unlink(temp_file_path)
        except Exception:
            pass
        try:
            os.unlink(cov_data_file)
        except Exception:
            pass

    return coverage_score, is_pass, covered_lines

# ==================== 统一实验配置 ====================
INITIAL_SEEDS = 10
GENERATIONS = 4
OFFSPRING_PER_GEN = 10
TOTAL_BUDGET = INITIAL_SEEDS + GENERATIONS * OFFSPRING_PER_GEN  # = 50

# ==================== 评估配置 ====================
SEED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed")

# 当前测试的数据集（如果要测试多个，可以循环）
EVOlfuzzer_JSONL = os.path.join(SEED_DIR, "fuzz_test_evolfuzzer.jsonl")
ATHERIS_JSONL = os.path.join(SEED_DIR, "fuzz_test_atheris.jsonl")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def convert_to_float(obj):
    """递归将 Decimal 转换为 float"""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_to_float(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_float(v) for v in obj]
    return obj


def load_jsonl(path):
    """加载 .jsonl 文件"""
    records = []
    if not os.path.exists(path):
        print("      [WARN] 文件不存在: {}".format(path))
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


def run_evaluation_for_method(jsonl_path, output_folder, method_label, dataset_label=""):
    """
    读取 jsonl_path，对每条记录调用 execute_test_case，
    将崩溃写入 output_folder，返回统计摘要。
    """
    # 每次评估前清空旧结果
    if os.path.exists(output_folder):
        for old_file in glob.glob(os.path.join(output_folder, "*.json")):
            os.remove(old_file)
    else:
        os.makedirs(output_folder, exist_ok=True)

    print("      输出目录: {}".format(os.path.abspath(output_folder)))

    records = load_jsonl(jsonl_path)
    print("    [{}] 共加载 {} 条记录".format(method_label, len(records)))

    total_inputs = 0
    total_crashes = 0
    total_load_errors = 0

    for record in tqdm(records, desc="      {}".format(method_label), unit="record", leave=False):
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
                # 使用内联的崩溃检测函数
                coverage_score, is_pass, covered_lines = execute_and_detect_crashes(
                    code, test_input_converted, os.path.abspath(output_folder))
                # 如果测试不通过（触发异常），应该有崩溃
                if not is_pass:
                    total_crashes += 1
            except Exception as e:
                # 如果 execute_test_case 内部没有捕获异常，说明代码加载失败
                print(f"      [DEBUG] 代码加载失败: {e}")
                total_load_errors += 1
                pass

    crash_count, type_counter = count_crashes_in_folder(output_folder)
    print("    [{}] 汇总: 总输入={}, 检测到异常={}, 代码加载失败={}, 保存的崩溃数={}".format(
        method_label, total_inputs, total_crashes, total_load_errors, crash_count))

    return {
        "method": method_label,
        "dataset": dataset_label,
        "total_inputs": total_inputs,
        "total_crashes": total_crashes,
        "unique_crashes": crash_count,
        "type_counter": dict(type_counter),
    }


def generate_atheris_seeds(dataset_dir, dataset_name, vulnerability_file):
    """
    为指定数据集运行 Atheris 种子生成。
    输出到 dataset_dir/fuzz_test_atheris.jsonl。
    """
    atheris_script = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "fuzz_with_atheris.py"
    )
    output_jsonl = os.path.join(dataset_dir, "fuzz_test_atheris.jsonl")

    if os.path.exists(output_jsonl):
        print("    [Atheris] 已有种子文件，跳过生成: {}".format(output_jsonl))
        return output_jsonl

    print("    [Atheris] 开始生成种子 (数据集: {}) ...".format(dataset_name))
    try:
        result = subprocess.run(
            [sys.executable, atheris_script],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env={
                **os.environ,
                "VULNERABILITY_DATA_FILE": vulnerability_file,
                "ATHERIS_OUTPUT_DIR": dataset_dir,
            },
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode == 0:
            print("    [Atheris] 种子生成完成")
        else:
            print("    [Atheris] 种子生成失败: {}".format(result.stderr[:200]))
    except subprocess.TimeoutExpired:
        print("    [Atheris] 种子生成超时（10分钟），跳过")
    except Exception as e:
        print("    [Atheris] 种子生成异常: {}".format(str(e)[:200]))

    return output_jsonl


def find_dataset_vulnerability_file(dataset_dir):
    """在数据集目录中查找 vulnerability_data.jsonl"""
    candidates = [
        os.path.join(dataset_dir, "vulnerability_data.jsonl"),
        os.path.join(dataset_dir, "..", "vulnerability_data.jsonl"),
        os.path.join(dataset_dir, "..", "compare_with_atheris", "vulnerability_data.jsonl"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def print_comparison_table(all_results):
    """打印对比表格"""

    # ------ 表1: 总体对比 ------
    print("\n" + "=" * 90)
    print("  表 R2: EvoLFuzzer vs Atheris (Google SOTA Python Fuzzer) — Unique Crashes")
    print("=" * 90)

    header = "  {:<25} {:>15} {:>18}".format("Method", "Total Inputs", "Unique Crashes")
    print(header)
    print("  " + "-" * 90)

    for r in all_results:
        marker = " ★" if "EvoLFuzzer" in r["method"] else ""
        row = "  {:<25} {:>15} {:>18}{}".format(
            r['method'],
            r['total_inputs'],
            r['unique_crashes'],
            marker
        )
        print(row)

    print("=" * 90)

    # ------ 表2: 方法对比 ------
    print("\n  表 R3: 方法对比")
    print("  " + "-" * 70)

    evo = next((r for r in all_results if "EvoLFuzzer" in r["method"]), None)
    ath = next((r for r in all_results if "Atheris" in r["method"]), None)

    if evo and ath:
        if evo["unique_crashes"] > ath["unique_crashes"]:
            winner = "EvoLFuzzer 胜"
        elif ath["unique_crashes"] > evo["unique_crashes"]:
            winner = "Atheris 胜"
        else:
            winner = "平局"

        print("  EvoLFuzzer (Ours)     : 测试输入={:>5}, 唯一崩溃={:>5}".format(
            evo["total_inputs"], evo["unique_crashes"]))
        print("  Atheris (Google SOTA): 测试输入={:>5}, 唯一崩溃={:>5}".format(
            ath["total_inputs"], ath["unique_crashes"]))
        print("\n  结论: {}".format(winner))

        # 改进倍数
        if ath["unique_crashes"] > 0:
            ratio = evo["unique_crashes"] / ath["unique_crashes"]
            print("  EvoLFuzzer 相对 Atheris 改进: {:.2f}x".format(ratio))
        elif evo["unique_crashes"] > 0:
            print("  EvoLFuzzer 相对 Atheris 改进: ∞x (Atheris 未发现崩溃)")
        else:
            print("  两者均未发现崩溃")

    print()


def capture_output(func, *args, **kwargs):
    """捕获函数执行过程中的所有 print 输出"""
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        func(*args, **kwargs)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    reliability_guard(maximum_memory_bytes=2 ** 32)

    # 当前脚本所在目录
    current_dir = os.path.dirname(os.path.abspath(__file__))

    output_lines = []
    output_lines.append("=" * 80)
    output_lines.append("  EvoLFuzzer vs Atheris (Google SOTA Python Fuzzer)")
    output_lines.append("  Reviewer Response: 添加工业级模糊测试器基线")
    output_lines.append("=" * 80)
    output_lines.append("  实验配置:")
    output_lines.append("    - 统一执行预算: {} initial + {} generations × {} offspring = {} executions/task".format(
        INITIAL_SEEDS, GENERATIONS, OFFSPRING_PER_GEN, TOTAL_BUDGET
    ))
    output_lines.append("    - 路径去重策略: 仅保存发现新执行路径的测试用例")
    output_lines.append("    - 崩溃去重策略: 基于 crash ID 哈希去重")
    output_lines.append("    - Atheris: Google SOTA Python Fuzzer (覆盖率引导, 字节级变异)")
    output_lines.append("    - EvoLFuzzer: LLM 引导的语义模糊测试 (本工作)")
    output_lines.append("=" * 80)
    output_lines.append("")

    all_results = []

    print("\n" + "=" * 70)
    print("  评估目录: {}".format(SEED_DIR))
    print("=" * 70)

    output_lines.append("评估目录: {}".format(SEED_DIR))

    # ------ 1. 评估 EvoLFuzzer ------
    evo_output_folder = os.path.join(SEED_DIR, "crashes_evolfuzzer")
    if os.path.exists(EVOlfuzzer_JSONL):
        print("  [EvoLFuzzer] 评估中 ...")
        evo_result = run_evaluation_for_method(
            jsonl_path=EVOlfuzzer_JSONL,
            output_folder=evo_output_folder,
            method_label="EvoLFuzzer (Ours)",
            dataset_label="All",
        )
        all_results.append(evo_result)
        output_lines.append("  [EvoLFuzzer] 总测试输入数: {}, 唯一崩溃数: {}".format(
            evo_result["total_inputs"], evo_result["unique_crashes"]))
    else:
        print("  [EvoLFuzzer] 种子文件不存在: {}".format(EVOlfuzzer_JSONL))
        output_lines.append("  [EvoLFuzzer] 种子文件不存在: {}".format(EVOlfuzzer_JSONL))

    # ------ 2. 评估 Atheris ------
    ath_output_folder = os.path.join(SEED_DIR, "crashes_atheris")
    if os.path.exists(ATHERIS_JSONL):
        print("  [Atheris] 评估中 ...")
        ath_result = run_evaluation_for_method(
            jsonl_path=ATHERIS_JSONL,
            output_folder=ath_output_folder,
            method_label="Atheris (Google SOTA)",
            dataset_label="All",
        )
        all_results.append(ath_result)
        output_lines.append("  [Atheris] 总测试输入数: {}, 唯一崩溃数: {}".format(
            ath_result["total_inputs"], ath_result["unique_crashes"]))
    else:
        print("  [Atheris] 种子文件不存在: {}".format(ATHERIS_JSONL))
        output_lines.append("  [Atheris] 种子文件不存在: {}".format(ATHERIS_JSONL))

    # ------ 3. 打印对比表格 ------
    if all_results:
        table_output = capture_output(print_comparison_table, all_results)
        output_lines.append(table_output)
    else:
        output_lines.append("没有找到任何结果数据，请先运行种子生成脚本。")

    # ------ 5. 保存日志 ------
    full_output = "\n".join(output_lines)
    print(full_output)

    log_path = os.path.join(current_dir, "atheris_comparison_log.txt")
    with open(log_path, 'w', encoding='utf-8') as f:
        f.write(full_output)

    print("\n评估结果已保存至: {}".format(os.path.abspath(log_path)))

    # ------ 6. 保存结构化结果 (JSON) ------
    json_path = os.path.join(current_dir, "atheris_comparison_results.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print("结构化结果已保存至: {}".format(os.path.abspath(json_path)))


if __name__ == "__main__":
    main()
