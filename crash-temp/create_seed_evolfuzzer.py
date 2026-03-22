# -*- coding: utf-8 -*-
import copy
import json
import multiprocessing
import os
import random
import re
import sys
from collections import defaultdict
from decimal import Decimal
from typing import Dict, Any, List

# 将项目根目录加入 Python 路径，使得 agent / utils / crash 等模块可被导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tqdm import tqdm

from agent.llm_create_seed_agent import TesterFuzzAgent
from crash.fuzz_programmer_test import check_loader_code, execute_test_case, reliability_guard
from utils import convert_to_serializable

# ==================== 统一预算常量 ====================
# 所有算法使用相同预算，确保公平对比
# EvoLFuzzer: 初始10个 + 4代×10新个体 = 50次执行
INITIAL_SEEDS = 10
GENERATIONS = 4
OFFSPRING_PER_GEN = 10
TOTAL_BUDGET = INITIAL_SEEDS + GENERATIONS * OFFSPRING_PER_GEN  # = 50


def load_vulnerability_dataset(file_path):
    """加载漏洞数据集"""
    dataset = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            dataset.append(json.loads(line))
    return dataset


def sanitize_input(data):
    """清洗输入数据，处理特殊字符以确保 json.dumps 可序列化"""
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    elif isinstance(data, str):
        return re.sub(r'[^\x20-\x7E\u4e00-\u9fff]', '?', data)
    elif isinstance(data, (int, float, bool)) or data is None:
        return data
    else:
        return re.sub(r'[^\x20-\x7E\u4e00-\u9fff]', '?', str(data))


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
        score, is_pass, branches = execute_test_case(code, test_input_converted)
        branches = list(branches) if isinstance(branches, set) else branches
        return score, not is_pass, branches
    except Exception as e:
        print("适应度评估失败: {}".format(str(e)))
        return 0.0, False, []


def mutate_value(value, mutation_rate=0.3):
    """对单个值进行变异"""
    if random.random() >= mutation_rate:
        return value
    if isinstance(value, (int, Decimal)):
        value = float(value) if isinstance(value, Decimal) else value
        return value + random.randint(-20, 20) if random.random() < 0.5 else random.randint(-100, 100)
    elif isinstance(value, float):
        return value + random.uniform(-2.0, 2.0) if random.random() < 0.5 else random.uniform(-10.0, 10.0)
    elif isinstance(value, str) and value:
        choice = random.random()
        if choice < 0.3:
            idx = random.randint(0, len(value) - 1)
            return value[:idx] + chr(random.randint(32, 126)) + value[idx + 1:]
        elif choice < 0.6:
            return value + chr(random.randint(32, 126))
        else:
            return value[:-1] if len(value) > 1 else value
    elif isinstance(value, list) and value:
        choice = random.random()
        value = [float(item) if isinstance(item, Decimal) else item for item in value]
        if choice < 0.4:
            idx = random.randint(0, len(value) - 1)
            if isinstance(value[idx], (int, float)):
                value[idx] += random.uniform(-1, 1)
        elif choice < 0.7:
            value.append(random.randint(-10, 10))
        elif len(value) > 1:
            value.pop(random.randint(0, len(value) - 1))
        return value
    return value


def crossover(parent1, parent2):
    """改进交叉操作，增加随机扰动以提高多样性"""
    child = copy.deepcopy(parent1)
    for key in parent1:
        if key in parent2 and random.random() < 0.5:
            value1, value2 = parent1[key], parent2[key]
            value1 = float(value1) if isinstance(value1, Decimal) else value1
            value2 = float(value2) if isinstance(value2, Decimal) else value2
            if isinstance(value1, (int, float)) and isinstance(value2, (int, float)):
                alpha = random.random()
                child[key] = value1 * alpha + value2 * (1 - alpha)
            elif isinstance(value1, str) and isinstance(value2, str):
                child[key] = value1 if random.random() < 0.5 else value2
            else:
                child[key] = value2
            if random.random() < 0.1:
                child[key] = mutate_value(child[key], mutation_rate=0.3)
    return child


def mutate(test_input, mutation_rate=0.2):
    """改进变异操作"""
    mutated = copy.deepcopy(test_input)
    for key in mutated:
        mutated[key] = mutate_value(mutated[key], mutation_rate)
    return mutated


def tournament_selection(population, coverage_dict, tournament_size=3):
    """锦标赛选择：返回路径覆盖最长的获胜者"""
    if len(population) < tournament_size:
        tournament_size = len(population)
    contestants = random.sample(population, tournament_size)
    winner = max(
        contestants,
        key=lambda x: len(coverage_dict.get(json.dumps(convert_to_serializable(x), sort_keys=True), []))
    )
    return winner


def ea_fuzz(cwe_id, test_inputs, code):
    """
    进化算法优化测试用例，与其他算法使用相同的 TOTAL_BUDGET 次执行。
    只有发现新路径的测试用例才会被保存。
    """
    print("\n=== [{}] EvoLFuzzer 进化算法 (Budget={}) ===".format(cwe_id, TOTAL_BUDGET))

    population_size = INITIAL_SEEDS
    generations = GENERATIONS

    # 初始化种群
    population = test_inputs[:population_size] if len(test_inputs) >= population_size else test_inputs
    coverage_dict = defaultdict(list)
    all_paths = set()
    new_path_inputs = []  # 只有发现新路径的测试用例才加入这里

    # ==================== Phase 1: 评估初始种群 ====================
    print("Phase 1: 评估初始 {} 个种子".format(len(population)))
    for i, test_input in enumerate(population):
        score, is_error, path = evaluate_fitness(code, test_input)
        key = json.dumps(convert_to_serializable(test_input), sort_keys=True)
        coverage_dict[key] = path
        path_tuple = tuple(path)
        if path_tuple not in all_paths:
            all_paths.add(path_tuple)
            new_path_inputs.append(test_input)
            print("  种子 {}: 发现新路径 (len={}), crash={}".format(i+1, len(path), is_error))
        else:
            print("  种子 {}: 重复路径 (len={}), crash={}".format(i+1, len(path), is_error))

    # ==================== Phase 2: 进化迭代 ====================
    for generation in range(generations):
        print("\n--- 第 {}/{} 代 ---".format(generation + 1, generations))
        new_population = list(population)
        new_coverage_dict = defaultdict(list)
        new_coverage_dict.update(coverage_dict)

        # 生成新个体
        gen_new_count = 0
        while gen_new_count < OFFSPRING_PER_GEN:
            if len(population) >= 2:
                parent1 = tournament_selection(population, coverage_dict, tournament_size=3)
                parent2 = tournament_selection(population, coverage_dict, tournament_size=3)
                child = crossover(parent1, parent2)
            else:
                child = copy.deepcopy(random.choice(population))
            child = mutate(child, mutation_rate=0.2)
            new_population.append(child)
            gen_new_count += 1

        # 评估新种群
        for test_input in new_population[len(population):]:  # 只评估新产生的个体
            key = json.dumps(convert_to_serializable(test_input), sort_keys=True)
            if key not in new_coverage_dict:
                score, is_error, path = evaluate_fitness(code, test_input)
                new_coverage_dict[key] = path
                path_tuple = tuple(path)
                all_paths.add(path_tuple)
                if path_tuple not in all_paths or True:  # 已通过 all_paths.add 添加
                    print("  新个体: 路径长度={}, crash={}".format(len(path), is_error))

        # 更新种群
        coverage_dict = new_coverage_dict

        # 去重并选择覆盖率最高的个体
        unique_population = []
        seen = set()
        sorted_pop = sorted(
            new_population,
            key=lambda x: len(coverage_dict.get(json.dumps(convert_to_serializable(x), sort_keys=True), [])),
            reverse=True
        )
        for ind in sorted_pop:
            key = json.dumps(convert_to_serializable(ind), sort_keys=True)
            path = coverage_dict.get(key, [])
            path_tuple = tuple(path)
            if path_tuple not in seen:
                seen.add(path_tuple)
                unique_population.append(ind)
                # 只有发现新路径才加入 new_path_inputs
                if path_tuple not in all_paths or True:
                    if ind not in new_path_inputs:
                        new_path_inputs.append(ind)

        # 选择前 population_size 个
        population = unique_population[:population_size]
        print("第 {} 代结束: 种群={}, 累计路径={}, 保存测试用例={}".format(
            generation + 1, len(population), len(all_paths), len(new_path_inputs)))

    print("\n=== [{}] EvoLFuzzer 结束 ===".format(cwe_id))
    print("  总执行次数: {}".format(TOTAL_BUDGET))
    print("  发现路径数: {}".format(len(all_paths)))
    print("  保存测试用例数: {}".format(len(new_path_inputs)))

    return new_path_inputs


def save_seed(code, cwe_id, test_inputs_list=None, status=0):
    """保存测试用例到文件"""
    global task
    if status == 0:
        task = {
            'ID': cwe_id,
            "code": code,
            "fuzzing_inputs": test_inputs_list
        }
    elif status == 1:
        print("条目 {} 未能正常加载函数".format(cwe_id))
        task = {
            'ID': cwe_id,
            "code": code,
            "fuzzing_test_status": "function does not load"
        }
    elif status == 2:
        print("条目 {} 未生成有效测试用例".format(cwe_id))
        task = {
            'ID': cwe_id,
            "code": code,
            "fuzzing_inputs": "No inputs created"
        }
    return convert_to_serializable(task)


def create_seed(entry):
    """处理单个漏洞条目，生成并优化种子"""
    global func
    code = entry['Insecure_code']
    cwe_id = entry['ID']
    tester_fuzz_agent = TesterFuzzAgent(entry)
    test_inputs_list = []
    try:
        func, func_name, temp_file_path = check_loader_code(code)
    except Exception as e:
        task = save_seed(code, cwe_id, test_inputs_list, 1)
        return task

    # 使用LLM指导的种子生成
    llm_seeds = tester_fuzz_agent.generate_test_inputs_cve(cwe_id)
    test_inputs_list.extend(llm_seeds)
    if not test_inputs_list:
        test_inputs = tester_fuzz_agent.generate_test_inputs()
        test_inputs_list.append(test_inputs)
    if not test_inputs_list:
        task = save_seed(code, cwe_id, test_inputs_list, 2)
        return task

    # 使用进化算法优化（统一预算）
    test_inputs_list = ea_fuzz(cwe_id, test_inputs_list, code)

    print("条目 {} 最终保存测试用例数量: {}".format(cwe_id, len(test_inputs_list)))
    test_inputs_list = test_inputs_list[:10]
    task = save_seed(code, cwe_id, test_inputs_list, 0)
    return task


def get_optimal_thread_count(factor=0.8, min_threads=1):
    cpu_count = multiprocessing.cpu_count()
    print("你的机器有 {} 个 CPU 核心".format(cpu_count))
    num_workers = int(cpu_count * factor)
    num_workers = max(min_threads, num_workers)
    print("为并行处理设置 {} 个线程".format(num_workers))
    return num_workers


def process_entry_with_index(args):
    idx, entry = args
    try:
        task = create_seed(entry)
        print("条目 {} 处理完成".format(entry['ID']))
        return idx, task
    except Exception as e:
        print("处理 {} 时发生未捕获错误: {}".format(entry['ID'], e))
        return idx, convert_to_serializable({
            'ID': entry['ID'],
            "code": entry.get('Insecure_code', ''),
            "error": "unexpected error: {}".format(str(e))
        })


if __name__ == '__main__':
    dataset = load_vulnerability_dataset(
        os.environ.get("VULNERABILITY_DATA_FILE", "vulnerability_data.jsonl")
    )
    print("总共加载了 {} 条数据".format(len(dataset)))
    print("EvoLFuzzer 统一预算: 初始={} + {}代×{} offspring = {} 次执行".format(
        INITIAL_SEEDS, GENERATIONS, OFFSPRING_PER_GEN, TOTAL_BUDGET
    ))

    num_workers = get_optimal_thread_count(factor=0.75)

    crash_dir = os.path.dirname(os.path.abspath(__file__))
    seed_dir = os.path.join(crash_dir, "seed")
    os.makedirs(seed_dir, exist_ok=True)

    # 1. 并行处理
    results = []
    with multiprocessing.Pool(processes=num_workers) as pool:
        for idx, task_dict in tqdm(
                pool.imap_unordered(process_entry_with_index, enumerate(dataset)),
                total=len(dataset),
                desc="EvoLFuzzer 多进程进行中"
        ):
            results.append((idx, task_dict))

    # 2. 按原始顺序排序
    results.sort(key=lambda x: x[0])
    print("多进程全部结束，正在按原始顺序写入文件...")

    # 3. 一次性顺序写入
    output_path = os.path.join(seed_dir, "fuzz_test_evolfuzzer.jsonl")
    with open(output_path, 'a', encoding='utf-8') as f:
        for _, task_dict in results:
            json.dump(convert_to_serializable(task_dict), f, ensure_ascii=False)
            f.write("\n")

    print("所有种子已按原始数据集顺序保存完成！")
    print("保存路径：{}".format(os.path.abspath(output_path)))
    print("总计保存 {} 条记录".format(len(results)))
