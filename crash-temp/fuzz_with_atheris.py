# -*- coding: utf-8 -*-
"""
fuzz_with_atheris.py
====================
使用 Google Atheris (SOTA Python Fuzzer) 为每个数据集条目生成测试用例种子。

Atheris 是 Google 开发的 Python 专用覆盖率引导模糊测试工具，
被广泛认为是 Python 生态中最先进的模糊测试引擎。

实验设计（与 EvoLFuzzer 统一 Budget）:
  - Budget per task: 10 initial + 4 generations × 10 offspring = 50 executions
  - Phase 1: 边界值初始种子建立基础覆盖率
  - Phase 2: Atheris 字节级覆盖率引导 fuzzing（libFuzzer 后端）
  - Phase 3: 收集所有通过/不抛异常的输入作为测试用例

Architecture:
  - 每个数据集条目在一个独立的子进程中运行 atheris.Setup()
  - 父进程负责任务分发、初始种子生成和结果汇总
  - 子进程通过 stdout 返回 JSON 格式结果

Usage:
    python fuzz_with_atheris.py
    # 或指定数据集路径:
    VULNERABILITY_DATA_FILE=path/to/dataset.jsonl python fuzz_with_atheris.py
"""

import importlib
import importlib.util
import json
import os
import random
import re
import subprocess
import sys
import tempfile
from decimal import Decimal
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from utils import convert_to_serializable

# ==================== 统一预算常量 ====================
INITIAL_SEEDS = 10
GENERATIONS = 4
OFFSPRING_PER_GEN = 10
TOTAL_BUDGET = INITIAL_SEEDS + GENERATIONS * OFFSPRING_PER_GEN  # = 50


# ---------------------------------------------------------------------------
# 子进程入口：运行单条目的 atheris fuzzing（每个条目独立进程，Setup 只调用一次）
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 子进程入口脚本（固定不变，读取临时参数文件）
# ---------------------------------------------------------------------------

_SUBPROCESS_BOOTSTRAP = """
import importlib, importlib.util, json, os, random, sys, tempfile
from decimal import Decimal

ATHERIS_RUNS = int(sys.argv[1])
PARAM_FILE = sys.argv[2]

with open(PARAM_FILE, 'r', encoding='utf-8') as f:
    data = json.load(f)

code = data['code']
cwe_id = data['cwe_id']
param_names = data['param_names']
param_types = data['param_types']
initial_seeds = data['initial_seeds']

def sanitize_input(data):
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(i) for i in data]
    elif isinstance(data, str):
        return __import__('re').sub(r'[^\\x20-\\u9fff]', '?', data)
    elif isinstance(data, (int, float, bool)) or data is None:
        return data
    else:
        return __import__('re').sub(r'[^\\x20-\\u9fff]', '?', str(data))

def generate_typed_value(type_hint):
    t = type_hint.lower().strip()
    if 'int' in t:
        return random.choice([0, 1, -1, 42, 100, -100, 2**31-1, 2**31, 2**63-1])
    elif 'float' in t or 'double' in t:
        return random.choice([0.0, 1.5, -1.5, float('inf'), float('-inf'), float('nan'), 1e308, -1e308])
    elif 'bool' in t:
        return random.choice([True, False])
    elif 'str' in t:
        return random.choice(['', 'test', 'hello', '<script>alert(1)</script>', 'a'*1000,
                             '\\x00\\x01\\x02', 'null', 'undefined', 'DROP TABLE users;',
                             '../../etc/passwd', '{{ .{{.Env}}}}'])
    elif 'list' in t or 'sequence' in t:
        inner = 'int' if 'int' in t else ('str' if 'str' in t else 'float')
        return [generate_typed_value(inner) for _ in range(random.randint(0, 5))]
    elif 'dict' in t or 'mapping' in t:
        return {'key': generate_typed_value('str')}
    else:
        return random.choice([0, 1.0, '', [], {}, None, True])

def load_target(code):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write(code)
        path = f.name
    spec = importlib.util.spec_from_file_location("mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    names = [l.split('(')[0].replace('def ', '').strip()
             for l in code.splitlines() if l.strip().startswith('def')]
    return getattr(mod, names[0])

# Phase 1: 初始种子执行，收集通过的输入
target_func = load_target(code)
all_passed = []
for seed in initial_seeds:
    seed_c = {k: float(v) if isinstance(v, Decimal) else v for k, v in seed.items()}
    try:
        target_func(**seed_c)
        all_passed.append(sanitize_input(seed_c))
    except Exception:
        pass

# Phase 2: Atheris fuzzing
import atheris
collected = []

def test_one_input(fuzz_bytes):
    test_input = None
    try:
        inp_data = json.loads(fuzz_bytes.decode('utf-8', errors='ignore'))
        if not isinstance(inp_data, dict):
            inp_data = {}
        test_input = {}
        for name, t in zip(param_names, param_types):
            raw = inp_data.get(name, None)
            if raw is None:
                raw = generate_typed_value(t)
            elif isinstance(raw, Decimal):
                raw = float(raw)
            test_input[name] = raw
        target_func(**test_input)
        collected.append(("pass", sanitize_input(test_input)))
    except Exception as e:
        # 记录崩溃用例！Atheris 不会自动记录崩溃，需要手动保存
        # 只有当 test_input 成功构建时才记录
        if test_input is not None:
            collected.append(("crash", sanitize_input(test_input)))

sys.argv = [sys.argv[0], f'-atheris_runs={ATHERIS_RUNS}']
try:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
except SystemExit:
    pass

# 分离通过和崩溃的用例
passed_inputs = []
crash_inputs = []
for tag, inp in collected:
    if tag == "pass":
        passed_inputs.append(inp)
    else:
        crash_inputs.append(inp)

# 合并去重并输出：同时保存通过的用例和崩溃的用例
seen_pass = {}
seen_crash = {}
for x in all_passed + passed_inputs:
    key = json.dumps(x, sort_keys=True, ensure_ascii=False)
    seen_pass[key] = x
for x in crash_inputs:
    key = json.dumps(x, sort_keys=True, ensure_ascii=False)
    seen_crash[key] = x

all_inputs = list(seen_pass.values())[:10] + list(seen_crash.values())
result = all_inputs[:10]  # 最多保留10个测试用例
print(json.dumps({
    "test_inputs": result,
    "crash_inputs": list(seen_crash.values())[:10],
    "cwe_id": cwe_id,
    "stats": {"passed": len(seen_pass), "crashes": len(seen_crash)}
}, ensure_ascii=False))
"""


# ---------------------------------------------------------------------------
# 子进程调用
# ---------------------------------------------------------------------------

def _run_atheris_subprocess(entry: Dict[str, Any], timeout: int = 120) -> Dict[str, Any]:
    """
    在子进程中执行单条目 Atheris fuzzing。
    通过临时 JSON 文件传参（避免命令行转义问题），超时控制防止个别条目卡死。
    """
    cwe_id = entry.get('ID', 'unknown')

    # 将参数写入临时文件（避免命令行引号转义问题）
    param_file = tempfile.NamedTemporaryFile(
        mode='w', suffix='.json', delete=False, encoding='utf-8'
    )
    try:
        json.dump({
            'code': entry['code'],
            'cwe_id': cwe_id,
            'param_names': entry['param_names'],
            'param_types': entry['param_types'],
            'initial_seeds': entry['initial_seeds'],
        }, param_file, ensure_ascii=False)
        param_file.close()

        proc = subprocess.run(
            [sys.executable, '-c', _SUBPROCESS_BOOTSTRAP,
             str(OFFSPRING_PER_GEN * GENERATIONS), param_file.name],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout.strip())
        else:
            err = (proc.stderr or '').strip()
            out = (proc.stdout or '').strip()
            # 常见非致命错误忽略，但打印诊断信息
            ignored = ['Setup() must not be called', 'SIGALRM', 'libFuzzer']
            for tag in ignored:
                if tag in err and not out:
                    print(f"  [DIAG] {cwe_id}: ignored error tag '{tag}'")
                    return {"test_inputs": [], "cwe_id": cwe_id}
            # 打印完整错误信息
            print(f"  [DIAG] {cwe_id}: returncode={proc.returncode}, stdout={out[:100] if out else '(empty)'}, stderr={err[:200] if err else '(empty)'}")
            return {
                "test_inputs": [],
                "cwe_id": cwe_id,
                "error": err[:500] if err else f"returncode={proc.returncode}, stdout={out[:100]}",
            }
    except subprocess.TimeoutExpired:
        return {"test_inputs": [], "cwe_id": cwe_id, "error": f"timeout after {timeout}s"}
    except json.JSONDecodeError as e:
        return {"test_inputs": [], "cwe_id": cwe_id, "error": f"JSON decode error: {e}"}
    except Exception as e:
        return {"test_inputs": [], "cwe_id": cwe_id, "error": str(e)}
    finally:
        try:
            os.unlink(param_file.name)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def load_vulnerability_dataset(file_path: str) -> List[Dict[str, Any]]:
    dataset = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            dataset.append(json.loads(line))
    return dataset


def extract_func_params(code: str) -> List[tuple]:
    results = []
    for line in code.splitlines():
        line = line.strip()
        if line.startswith('def '):
            inner = line[4:]
            paren_idx = inner.find('(')
            close_idx = inner.rfind(')')
            if paren_idx == -1 or close_idx == -1:
                continue
            args_str = inner[paren_idx + 1:close_idx]
            for arg in args_str.split(','):
                arg = arg.strip()
                if not arg:
                    continue
                if ':' in arg:
                    name = arg.split(':')[0].strip()
                    type_str = arg.split(':')[1].strip().split('=')[0].strip()
                else:
                    name = arg.split('=')[0].strip()
                    type_str = 'Any'
                results.append((name, type_str))
    return results


def generate_initial_seeds(param_names: List[str], param_types: List[str], count: int) -> List[Dict[str, Any]]:
    """生成边界值初始测试用例"""
    strategies = [
        lambda t: 0 if 'int' in t.lower() else (0.0 if 'float' in t.lower() else ''),
        lambda t: -1 if 'int' in t.lower() else (-1.0 if 'float' in t.lower() else 'a'),
        lambda t: 1 if 'int' in t.lower() else (1.0 if 'float' in t.lower() else 'test'),
        lambda t: None,
        lambda t: [] if 'list' in t.lower() else ({'v': 0} if 'dict' in t.lower() else 0),
    ]
    seeds = []
    for i in range(count):
        test_input = {}
        for j, (name, ptype) in enumerate(zip(param_names, param_types)):
            if i < len(strategies):
                test_input[name] = strategies[i % len(strategies)](ptype)
            else:
                test_input[name] = None
        seeds.append(test_input)
    return seeds


def save_seed_entry(cwe_id: str, code: str, test_inputs_list: List[Dict[str, Any]], status: int = 0) -> Dict[str, Any]:
    if status == 0:
        task = {'ID': cwe_id, 'code': code, 'fuzzing_inputs': test_inputs_list}
    elif status == 1:
        task = {'ID': cwe_id, 'code': code, 'fuzzing_test_status': 'function does not load'}
    else:
        task = {'ID': cwe_id, 'code': code, 'fuzzing_inputs': 'No inputs created'}
    return convert_to_serializable(task)


# ---------------------------------------------------------------------------
# 任务分发
# ---------------------------------------------------------------------------

def process_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """在独立子进程中运行单条目 Atheris fuzzing"""
    code = entry.get('Insecure_code', entry.get('code', ''))
    cwe_id = entry.get('ID', 'unknown')

    params = extract_func_params(code)
    if not params:
        return save_seed_entry(cwe_id, code, [], 2)

    param_names = [p[0] for p in params]
    param_types = [p[1] for p in params]

    try:
        target_func, _, _ = _check_loader_code(code)
    except Exception:
        return save_seed_entry(cwe_id, code, [], 1)

    initial_seeds = generate_initial_seeds(param_names, param_types, INITIAL_SEEDS)

    sub_entry = {
        'code': code,
        'cwe_id': cwe_id,
        'param_names': param_names,
        'param_types': param_types,
        'initial_seeds': initial_seeds,
    }
    result = _run_atheris_subprocess(sub_entry)
    test_inputs = result.get('test_inputs', [])
    crash_inputs = result.get('crash_inputs', [])
    error_msg = result.get('error', '')
    stats = result.get('stats', {})
    passed_count = stats.get('passed', 0)
    crash_count = stats.get('crashes', 0)

    # 打印错误信息以便调试
    if error_msg:
        print(f"  [WARN] {cwe_id} 子进程错误: {error_msg[:200]}")

    if not test_inputs and not crash_inputs:
        return save_seed_entry(cwe_id, code, [], 2)

    # 合并通过和崩溃的测试用例
    all_inputs = test_inputs + crash_inputs
    # 去重
    seen = {}
    for inp in all_inputs:
        key = json.dumps(inp, sort_keys=True, ensure_ascii=False)
        seen[key] = inp
    unique_inputs = list(seen.values())

    print(f"  [{cwe_id}] Atheris: 通过={passed_count}, 崩溃={crash_count}, 总用例={len(unique_inputs)}")
    return save_seed_entry(cwe_id, code, unique_inputs[:10], 0)


def _check_loader_code(code: str):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
        temp_file.write(code)
        temp_file_path = temp_file.name

    spec = importlib.util.spec_from_file_location("check_temp_module", temp_file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    func_names = [
        line.split('(')[0].replace('def ', '').strip()
        for line in code.splitlines() if line.strip().startswith('def')
    ]
    func_name = func_names[0]
    func = getattr(module, func_name)
    return func, func_name, temp_file_path


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def main():
    dataset = load_vulnerability_dataset(
        os.environ.get("VULNERABILITY_DATA_FILE", "vulnerability_data.jsonl")
    )
    print("=" * 70)
    print("  Atheris Fuzzing (Google SOTA Python Fuzzer)")
    print("=" * 70)
    print(f"  数据集: {len(dataset)} 条")
    print(f"  统一 Budget: {INITIAL_SEEDS} initial + {GENERATIONS} gen × {OFFSPRING_PER_GEN} = {TOTAL_BUDGET}")
    print(f"  Atheris 迭代上限: {OFFSPRING_PER_GEN * GENERATIONS}")
    print("  每个条目独立子进程（避免 Setup() 重复调用）")
    print("=" * 70)

    results = []
    for i, entry in enumerate(dataset):
        cwe_id = entry.get('ID', f'entry_{i}')
        print(f"\n[{i+1}/{len(dataset)}] 处理 {cwe_id} ...", flush=True)
        try:
            result = process_entry(entry)
            results.append((i, result))
            print(f"  完成: {cwe_id}")
        except Exception as e:
            print(f"  错误: {cwe_id} - {e}")
            results.append((i, {
                'ID': cwe_id,
                'code': entry.get('Insecure_code', ''),
                'error': str(e)
            }))

    results.sort(key=lambda x: x[0])

    crash_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(crash_dir, "fuzz_test_atheris.jsonl")
    with open(output_path, 'w', encoding='utf-8') as f:
        for _, task_dict in results:
            json.dump(task_dict, f, ensure_ascii=False)
            f.write("\n")

    print(f"\n所有 Atheris 测试用例已保存至: {output_path}")
    print(f"总计: {len(results)} 条记录")


if __name__ == "__main__":
    main()
