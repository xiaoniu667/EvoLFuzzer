# -*- coding: utf-8 -*-
import json
import multiprocessing
import os
import random
import string
import sys
from copy import deepcopy
from decimal import Decimal
from multiprocessing import Pool
from typing import Dict, Any, List, Tuple

# 将项目根目录加入 Python 路径，使得 agent / utils / crash 等模块可被导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tqdm import tqdm

from agent.llm_create_seed_agent import TesterFuzzAgent
from crash.fuzz_programmer_test import check_loader_code, reliability_guard, execute_test_case
from utils import convert_to_serializable

# ==================== 统一预算常量 ====================
# 与 EvoLFuzzer 保持一致: 初始种子 + 进化代数 × 每代新个体
INITIAL_SEEDS = 10       # 初始测试用例数量
GENERATIONS = 4           # 进化代数
OFFSPRING_PER_GEN = 10   # 每代生成的新个体数
TOTAL_BUDGET = INITIAL_SEEDS + GENERATIONS * OFFSPRING_PER_GEN  # = 50


def convert_to_float(obj):
    """递归将 Decimal 转换为 float"""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_to_float(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_float(v) for v in obj]
    return obj


def evaluate_fitness(code, test_input):
    """评估适应度，返回分数、是否崩溃和分支覆盖"""
    try:
        test_input_converted = convert_to_float(test_input)
        score, is_error, branches = execute_test_case(code, test_input_converted)
        branches = list(branches) if isinstance(branches, set) else branches
        return score, is_error, branches
    except Exception as e:
        return 0.0, False, []


def mutate_value_rma(value):
    """根据值的类型对单个值进行随机变异"""
    if isinstance(value, bool):
        return value if random.random() > 0.5 else not value
    if isinstance(value, int):
        return value + random.randint(-1000, 1000)
    elif isinstance(value, float):
        return value + random.uniform(-1000.0, 1000.0)
    elif isinstance(value, str):
        if len(value) == 0:
            return ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 20)))
        mutation_type = random.choice(['shuffle', 'add', 'remove'])
        if mutation_type == 'shuffle':
            return ''.join(random.sample(value, len(value)))
        elif mutation_type == 'add':
            position = random.randint(0, len(value))
            return value[:position] + random.choice(string.ascii_letters + string.digits) + value[position:]
        elif mutation_type == 'remove' and len(value) > 1:
            position = random.randint(0, len(value) - 1)
            return value[:position] + value[position + 1:]
        else:
            return value
    elif isinstance(value, list):
        return [mutate_value_rma(element) for element in value]
    elif isinstance(value, dict):
        if len(value) == 0:
            return {mutate_value_rma(''): mutate_value_rma('')}
        mutation_type = random.choice(['mutate_key', 'mutate_value', 'add', 'remove'])
        if mutation_type == 'mutate_key':
            old_key = random.choice(list(value.keys()))
            new_key = mutate_value_rma(old_key)
            value[new_key] = value.pop(old_key)
        elif mutation_type == 'mutate_value':
            key = random.choice(list(value.keys()))
            value[key] = mutate_value_rma(value[key])
        elif mutation_type == 'add':
            value[mutate_value_rma('')] = mutate_value_rma('')
        elif mutation_type == 'remove' and len(value) > 1:
            key = random.choice(list(value.keys()))
            del value[key]
        return value
    else:
        return value


def mutate_inputs(inputs):
    """对 inputs 对象的内容进行随机变异"""
    mutated_inputs = {}
    try:
        for key, value in inputs.items():
            mutated_inputs[key] = mutate_value_rma(deepcopy(value))
    except AttributeError:
        if isinstance(inputs, list):
            inputs = {i: item for i, item in enumerate(inputs)}
        for key, value in inputs.items():
            mutated_inputs[key] = mutate_value_rma(deepcopy(value))
    return mutated_inputs


def load_vulnerability_dataset(file_path):
    dataset = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            dataset.append(json.loads(line))
    return dataset


def rma_fuzz(cwe_id, initial_seeds, code):
    """
    公平版随机搜索 (RMA)：执行与 EvoLFuzzer 相同的 TOTAL_BUDGET 次测试，
    只有发现新路径的测试用例才会被保存。

    参数:
        cwe_id: 漏洞ID
        initial_seeds: 初始测试用例列表
        code: 待测代码

    返回:
        List[Dict]: 发现新路径的测试用例（最多 TOTAL_BUDGET 个）
    """
    print("\n=== [{}] RMA 随机搜索 (Budget={}) ===".format(cwe_id, TOTAL_BUDGET))

    coverage_dict = {}  # input_key -> path(list)
    all_paths = set()   # 全局已发现路径集合
    new_path_inputs = []  # 只有发现新路径的测试用例才加入这里

    # ==================== Phase 1: 初始种子评估 ====================
    print("Phase 1: 评估初始 {} 个种子".format(min(len(initial_seeds), INITIAL_SEEDS)))
    seeds_to_eval = initial_seeds[:INITIAL_SEEDS] if len(initial_seeds) >= INITIAL_SEEDS else initial_seeds

    for i, seed in enumerate(seeds_to_eval):
        key = json.dumps(convert_to_serializable(seed), sort_keys=True)
        if key not in coverage_dict:
            score, is_error, path = evaluate_fitness(code, seed)
            coverage_dict[key] = path
            path_tuple = tuple(path)
            if path_tuple not in all_paths:
                all_paths.add(path_tuple)
                new_path_inputs.append(seed)
                print("  种子 {}: 发现新路径 (len={}), crash={}".format(i+1, len(path), is_error))
            else:
                print("  种子 {}: 重复路径 (len={}), crash={}".format(i+1, len(path), is_error))

    print("Phase 1 结束: 发现 {} 条路径, 保存 {} 个测试用例".format(len(all_paths), len(new_path_inputs)))

    # ==================== Phase 2: 随机变异搜索 (凑够 TOTAL_BUDGET 次执行) ====================
    # 剩余预算 = TOTAL_BUDGET - 已执行次数
    remaining = TOTAL_BUDGET - len(seeds_to_eval)
    current_input = seeds_to_eval[-1] if seeds_to_eval else initial_seeds[0] if initial_seeds else {}

    print("Phase 2: 随机变异搜索 (剩余预算={})".format(remaining))

    for i in range(remaining):
        # 随机变异当前输入
        mutated = mutate_inputs(current_input)
        key = json.dumps(convert_to_serializable(mutated), sort_keys=True)

        # 执行评估
        score, is_error, path = evaluate_fitness(code, mutated)
        coverage_dict[key] = path
        path_tuple = tuple(path)

        if path_tuple not in all_paths:
            all_paths.add(path_tuple)
            new_path_inputs.append(mutated)
            print("  变异 {}: 发现新路径 (len={}), crash={}".format(i+1, len(path), is_error))
        else:
            print("  变异 {}: 重复路径 (len={}), crash={}".format(i+1, len(path), is_error))

        # 更新当前输入（连续随机搜索）
        current_input = mutated

    print("\n=== [{}] RMA 结束 ===".format(cwe_id))
    print("  总执行次数: {}".format(TOTAL_BUDGET))
    print("  发现路径数: {}".format(len(all_paths)))
    print("  保存测试用例数: {}".format(len(new_path_inputs)))

    return new_path_inputs


def create_seed_and_return(entry):
    """处理单条 entry，返回要保存的 task 字典"""
    code = entry['Insecure_code']
    cve_id = entry['ID']
    test_inputs_list = []

    try:
        func = check_loader_code(code)
    except Exception as e:
        print("条目 {} 未能正常加载函数: {}".format(cve_id, e))
        return {
            'ID': cve_id,
            "code": code,
            "fuzzing_test_status": "function does not load",
            "error": str(e)
        }

    try:
        tester_fuzz_agent = TesterFuzzAgent(entry)
        test_inputs = tester_fuzz_agent.generate_test_inputs()
        test_inputs_list.append(test_inputs)
    except Exception as e:
        print("条目 {} 生成初始测试用例失败: {}".format(cve_id, e))

    if not test_inputs_list or not test_inputs_list[0]:
        return {
            'ID': cve_id,
            "code": code,
            "fuzzing_inputs": "No inputs created"
        }

    # 使用公平版 RMA（统一预算 + 路径去重）
    test_inputs_list = rma_fuzz(cve_id, test_inputs_list, code)

    # 限制最多保存 10 个测试用例
    test_inputs_list = test_inputs_list[:10]
    print("条目 {} 最终保存测试用例数量: {}".format(cve_id, len(test_inputs_list)))

    return {
        'ID': cve_id,
        "code": code,
        "fuzzing_inputs": test_inputs_list
    }


def process_entry_with_index(args):
    idx, entry = args
    try:
        task = create_seed_and_return(entry)
        print("条目 {} 处理完成".format(entry['ID']))
        return idx, task
    except Exception as e:
        print("处理 {} 时发生未捕获错误: {}".format(entry['ID'], e))
        return idx, {
            'ID': entry['ID'],
            "code": entry.get('Insecure_code', ''),
            "error": "unexpected error: {}".format(str(e))
        }


def get_optimal_thread_count(factor=0.8, min_threads=1):
    cpu_count = multiprocessing.cpu_count()
    print("你的机器有 {} 个 CPU 核心".format(cpu_count))
    num_workers = max(min_threads, int(cpu_count * factor))
    print("为并行处理设置 {} 个线程".format(num_workers))
    return num_workers


if __name__ == '__main__':
    reliability_guard(maximum_memory_bytes=2 ** 30)

    dataset = load_vulnerability_dataset(
        os.environ.get("VULNERABILITY_DATA_FILE", "vulnerability_data.jsonl")
    )
    print("总共加载了 {} 条数据".format(len(dataset)))
    print("RMA 统一预算: 初始={} + {}代×{} offspring = {} 次执行".format(
        INITIAL_SEEDS, GENERATIONS, OFFSPRING_PER_GEN, TOTAL_BUDGET
    ))

    num_workers = get_optimal_thread_count(factor=0.75)

    crash_dir = os.path.dirname(os.path.abspath(__file__))
    seed_dir = os.path.join(crash_dir, "seed")
    os.makedirs(seed_dir, exist_ok=True)

    results = []
    with Pool(processes=num_workers) as pool:
        for idx, task_dict in tqdm(
            pool.imap_unordered(process_entry_with_index, enumerate(dataset)),
            total=len(dataset),
            desc="RMA 多进程进行中"
        ):
            results.append((idx, task_dict))

    results.sort(key=lambda x: x[0])
    print("多进程全部结束，正在按原始顺序写入文件...")

    output_path = os.path.join(seed_dir, "fuzz_test_rma.jsonl")
    with open(output_path, 'a', encoding='utf-8') as f:
        for _, task_dict in results:
            json.dump(convert_to_serializable(task_dict), f, ensure_ascii=False)
            f.write("\n")

    print("所有种子已按原始数据集顺序保存完成！")
    print("保存路径：{}".format(os.path.abspath(output_path)))
    print("总计保存 {} 条记录".format(len(results)))
