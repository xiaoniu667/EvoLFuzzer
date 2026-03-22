# -*- coding: utf-8 -*-
import copy
import json
import multiprocessing
import os
import random
import re
import string
import sys
from collections import defaultdict
from decimal import Decimal
from typing import Dict, Any, List
from typing import Tuple

# 将项目根目录加入 Python 路径，使得 agent / utils / crash 等模块可被导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tqdm import tqdm
from agent.llm_create_seed_agent import TesterFuzzAgent
from crash.fuzz_programmer_test import check_loader_code, reliability_guard, execute_test_case
from utils import convert_to_serializable

# ==================== 统一预算常量 ====================
# 所有算法使用相同预算，确保公平对比
INITIAL_SEEDS = 10
GENERATIONS = 4
OFFSPRING_PER_GEN = 10
TOTAL_BUDGET = INITIAL_SEEDS + GENERATIONS * OFFSPRING_PER_GEN  # = 50


def load_vulnerability_dataset(file_path: str) -> List[Dict[str, Any]]:
    """加载漏洞数据集"""
    dataset = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            dataset.append(json.loads(line))
    return dataset


def mutate_value_rma(value):
    """根据值的类型对单个值进行变异。"""
    if isinstance(value, bool):
        # 以50%的概率随机翻转布尔值
        return value if random.random() > 0.5 else not value
    if isinstance(value, int):
        # 通过加减随机数对整数进行变异
        return value + random.randint(-1000, 1000)
    elif isinstance(value, float):
        # 通过加减随机浮点数对浮点数进行变异
        return value + random.uniform(-1000.0, 1000.0)
    elif isinstance(value, str):
        # 通过打乱、添加随机字符或删除字符对字符串进行变异
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
        # 对列表中的所有元素进行变异
        return [mutate_value_rma(element) for element in value]
    elif isinstance(value, dict):
        # 通过变异键或值、添加或删除键值对对字典进行变异
        if len(value) == 0:
            return {mutate_value_rma(''): mutate_value_rma('')}  # 如果字典为空，添加一个新的随机键值对
        mutation_type = random.choice(['mutate_key', 'mutate_value_rma', 'add', 'remove'])
        if mutation_type == 'mutate_key':
            old_key = random.choice(list(value.keys()))
            new_key = mutate_value_rma(old_key)
            value[new_key] = value.pop(old_key)
        elif mutation_type == 'mutate_value_rma':
            key = random.choice(list(value.keys()))
            value[key] = mutate_value_rma(value[key])
        elif mutation_type == 'add':
            value[mutate_value_rma('')] = mutate_value_rma('')
        elif mutation_type == 'remove' and len(value) > 1:
            key = random.choice(list(value.keys()))
            del value[key]
        return value
    else:
        return value  # 对于不支持的类型，原样返回


def mutate_inputs(inputs):
    """对动态`inputs`对象的内容进行变异。"""
    mutated_inputs = {}
    try:
        for key, value in inputs.items():
            mutated_inputs[key] = mutate_value_rma(copy.deepcopy(value))
    except AttributeError as e:
        print(f"错误: {e}。`inputs`对象不是字典。")
        if isinstance(inputs, list):
            inputs = {i: item for i, item in enumerate(inputs)}
        for key, value in inputs.items():
            mutated_inputs[key] = mutate_value_rma(copy.deepcopy(value))
    return mutated_inputs


def fuzz_function(inputs):
    """生成模糊输入并使用它们运行函数。"""
    # 提取并变异输入
    return mutate_inputs(inputs)


def sanitize_input(data: Any) -> Any:
    """清洗输入数据，处理特殊字符以确保 json.dumps 可序列化"""
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    elif isinstance(data, str):
        # 替换不可打印字符（只保留 ASCII 32-126 或常见 Unicode 字符）
        return re.sub(r'[^\x20-\x7E\u4e00-\u9fff]', '?', data)
    elif isinstance(data, (int, float, bool)) or data is None:
        return data
    else:
        # 将其他类型转换为字符串并清洗
        return re.sub(r'[^\x20-\x7E\u4e00-\u9fff]', '?', str(data))



def convert_to_float(obj: Any) -> Any:
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_to_float(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_float(v) for v in obj]
    return obj


# 交叉与变异（直接使用你原来的实现）
def crossover(parent1: Dict[str, Any], parent2: Dict[str, Any]) -> Dict[str, Any]:
    child = copy.deepcopy(parent1)
    for key in parent1:
        if key in parent2 and random.random() < 0.5:
            child[key] = parent2[key]
    return child



def evaluate_fitness(code: str, test_input: Dict[str, Any], execute_test_case) -> Tuple[float, bool, List[int]]:
    try:
        test_input_converted = convert_to_float(test_input)
        score, is_error, branches = execute_test_case(code, test_input_converted)
        branches = list(branches) if isinstance(branches, set) else branches
        return score, is_error, branches
    except Exception as e:
        print(f"适应度评估失败: {str(e)}")
        return 0.0, False, []



def mutate(test_input: Dict[str, Any], mutation_rate: float = 0.2) -> Dict[str, Any]:
    mutated = copy.deepcopy(test_input)
    for key in mutated:
        if random.random() < mutation_rate:
            mutated[key] = mutate_value(mutated[key], mutation_rate=1.0)  # 高概率彻底随机变异
    return mutated


def mutate_value(value: Any, mutation_rate: float) -> Any:
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


def filter_duplicate_results(population: List[Dict[str, Any]],
                             coverage_dict: defaultdict) -> List[Dict[str, Any]]:
    seen_paths = set()
    unique = []
    for ind in population:
        key = json.dumps(convert_to_serializable(ind), sort_keys=True)
        path = tuple(coverage_dict[key])
        if path not in seen_paths:
            seen_paths.add(path)
            unique.append(ind)
    return unique


# ======================  遗传算法======================
def genetic_algorithm_fuzz(
    cwe_id: str,
    seed_inputs: List[Dict[str, Any]],
    code: str,
    population_size: int = 10,   # 统一为 10
    generations: int = 4,        # 统一为 4
    crossover_rate: float = 0.8,
    mutation_rate: float = 0.3,
    elite_size: int = 3,         # 调整为 3
) -> List[Dict[str, Any]]:
    """
    标准的遗传算法实现（μ, λ） + 精英保留
    选择方式：轮盘赌（fitness proportionate）
    交叉方式：均匀交叉（每个键独立决定从哪个父代继承）
    变异方式：调用原来的 mutate()，变异概率为 mutation_rate
    """
    μ = population_size
    λ = OFFSPRING_PER_GEN  # 统一每代产生 10 个子代

    # ------------------- 初始化种群 -------------------
    population = seed_inputs[:μ] if len(seed_inputs) >= μ else seed_inputs[:]
    if len(population) < μ:
        population.extend([copy.deepcopy(random.choice(seed_inputs))
                           for _ in range(μ - len(population))])

    coverage_dict = defaultdict(list)
    all_paths = set()
    new_path_inputs = []  # 只有发现新路径的测试用例才保存

    # ------------------- 评估函数-------------------
    def evaluate(ind: Dict[str, Any]) -> Tuple[float, bool, List[int]]:
        key = json.dumps(convert_to_serializable(ind), sort_keys=True)
        if key in coverage_dict:
            path = coverage_dict[key]
            score, is_err, _ = evaluate_fitness(code, ind, execute_test_case)
            return score, is_err, path

        score, is_err, path = evaluate_fitness(code, ind, execute_test_case)
        path = list(path) if isinstance(path, set) else path
        coverage_dict[key] = path
        path_tuple = tuple(path)
        # 只有发现新路径才保存
        if path_tuple not in all_paths:
            all_paths.add(path_tuple)
            new_path_inputs.append(copy.deepcopy(ind))
        return score, is_err, path

    # 初始种群全部评估一次
    print("\n=== [{}] 遗传算法初始化种群 ({}, Budget={}) ===".format(cwe_id, len(population), TOTAL_BUDGET))
    fitness_list = []
    for ind in population:
        score, is_err, path = evaluate(ind)
        fitness_list.append(score)
        print("  初始个体: score={:<6.2f} crash={} path_len={}".format(score, is_err, len(path)))

    print("  初始评估结束: 发现 {} 条路径, 保存 {} 个测试用例".format(len(all_paths), len(new_path_inputs)))

    # ------------------- 遗传算法主循环 -------------------
    for gen in range(1, generations + 1):
        print(f"\n=== 第 {gen}/{generations} 代 ===")

        # ---- 1. 计算适应度----
        path_lens = [len(coverage_dict[json.dumps(convert_to_serializable(ind), sort_keys=True)])
                     for ind in population]
        # 为避免全零导致除零，给所有个体加一个极小的基数
        fitness = [length + 1e-6 for length in path_lens]

        # ---- 2. 精英保留 ----
        # 按覆盖长度排序，取前 elite_size 个直接进入下一代
        combined = list(zip(population, fitness, path_lens))
        combined.sort(key=lambda x: x[2], reverse=True)
        elites = [ind for ind, _, _ in combined[:elite_size]]

        # ---- 3. 轮盘赌选择父母产生子代 ----
        new_population = elites[:]

        # 生成 λ 个子代
        while len(new_population) < μ + λ:
            # 轮盘赌选两个父代（允许选到同一个）
            parent1 = random.choices(population, weights=fitness, k=1)[0]
            parent2 = random.choices(population, weights=fitness, k=1)[0]

            # 交叉
            child = copy.deepcopy(parent1)
            if random.random() < crossover_rate:
                child = crossover(parent1, parent2)

            # 变异
            if random.random() < mutation_rate:
                child = mutate(child, mutation_rate=0.4)

            new_population.append(child)

        # ---- 4. 评估新产生的个体----
        print("评估本代新个体（除精英外 {} 个）...".format(len(new_population) - len(elites)))
        for ind in new_population[len(elites):]:
            key = json.dumps(convert_to_serializable(ind), sort_keys=True)
            if key not in coverage_dict:
                score, is_err, path = evaluate(ind)
                print("  新个体: score={:<6.2f} crash={} path_len={}".format(score, is_err, len(path)))

        population = new_population

        # 去重（防止同一路径的完全相同输入占满种群）
        population = filter_duplicate_results(population, coverage_dict)

        print("第 {} 代结束: 种群大小={:2d} | 累计不同路径数={:3d} | 保存测试用例={}".format(
            gen, len(population), len(all_paths), len(new_path_inputs)))

    # ------------------- 最终结果 -------------------
    print("\n=== [{}] 遗传算法结束 ===".format(cwe_id))
    print("  总执行次数: {} | 发现路径数: {} | 保存测试用例数: {}".format(
        TOTAL_BUDGET, len(all_paths), len(new_path_inputs)))

    return new_path_inputs[:10]


def save_seed(code: str, cwe_id: str, test_inputs_list: List[Dict[str, Any]] = None, status: int = 0):
    """保存测试用例到文件"""
    global task
    if status == 0:
        task = {
            'ID': cwe_id,
            "code": code,
            "fuzzing_inputs": test_inputs_list
        }
    elif status == 1:
        print(f"条目 {cwe_id} 未能正常加载函数")
        task = {
            'ID': cwe_id,
            "code": code,
            "fuzzing_test_status": "function does not load"
        }
    elif status == 2:
        print(f"条目 {cwe_id} 未生成有效测试用例")
        task = {
            'ID': cwe_id,
            "code": code,
            "fuzzing_inputs": "No inputs created"
        }
    return task


def process_entry(entry: Dict[str, Any]):
    try:
        create_seed(entry)
    except Exception as e:
        print(f"处理 {entry['ID']} 时发生错误: {e}")


def create_seed(entry: Dict[str, Any]):
    """处理单个漏洞条目，生成并优化种子"""
    global func
    code = entry['Insecure_code']
    cwe_id = entry['ID']
    tester_fuzz_agent = TesterFuzzAgent(entry)
    test_inputs_list = []
    try:
        func, func_name, temp_file_path = check_loader_code(code)  # 检查并加载代码
    except Exception as e:
        task = save_seed(code, cwe_id, test_inputs_list, 1)
        return task
    test_inputs = tester_fuzz_agent.generate_test_inputs()  # 生成初始种子
    test_inputs_list.append(test_inputs)
    if not test_inputs_list:
        task = save_seed(code, cwe_id, test_inputs_list, 2)
        return task
    # 使用遗传算法
    test_inputs_list = genetic_algorithm_fuzz(cwe_id, test_inputs_list, code,
                                               population_size=10, generations=4)
    print(f"条目 {cwe_id} 变异后测试用例数量: {len(test_inputs_list)}")
    test_inputs_list = test_inputs_list[:10]
    task = save_seed(code, cwe_id, test_inputs_list, 0)
    return task


def get_optimal_thread_count(factor=0.8, min_threads=1):
    """
    自动根据机器的 CPU 核心数设置并行线程数。
    :param factor: 并行线程数占 CPU 核心数的比例，默认为 0.8（即 80% 的核心数）
    :param min_threads: 最小线程数，默认为 1
    :return: 返回合理的线程数
    """
    # 获取机器的 CPU 核心数
    cpu_count = multiprocessing.cpu_count()
    print(f"你的机器有 {cpu_count} 个 CPU 核心")
    # 设置最大线程数为 CPU 核心数的指定比例
    num_workers = int(cpu_count * factor)  # 根据 factor 设置比例
    num_workers = max(min_threads, num_workers)  # 确保至少有 min_threads 个线程
    print(f"为并行处理设置 {num_workers} 个线程")


def process_entry_with_index(args: Tuple[int, Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
    """
    接收 (index, entry)，返回 (index, task_dict)
    这样即使多进程乱序执行，最后也能按 index 排序恢复原始顺序
    """
    idx, entry = args
    try:
        task = create_seed(entry)
        print(f"条目 {entry['ID']} 处理完成")
        return idx, task
    except Exception as e:
        print(f"处理 {entry['ID']} 时发生未捕获错误: {e}")
        return idx, {
            'ID': entry['ID'],
            "code": entry.get('Insecure_code', ''),
            "error": f"unexpected error: {str(e)}"
        }


if __name__ == '__main__':
    reliability_guard()
    dataset = load_vulnerability_dataset(
        os.environ.get("VULNERABILITY_DATA_FILE", "vulnerability_data.jsonl")
    )
    print("总共加载了 {} 条数据".format(len(dataset)))
    print("GA 统一预算: pop={} + {}代×{} offspring = {} 次执行".format(10, 4, 10, TOTAL_BUDGET))
    num_workers = get_optimal_thread_count(factor=1)
    crash_dir = os.path.dirname(os.path.abspath(__file__))
    seed_dir = os.path.join(crash_dir, "seed")
    os.makedirs(seed_dir, exist_ok=True)
    # 1. 并行处理
    results = []
    with multiprocessing.Pool(processes=num_workers) as pool:
        for idx, task_dict in tqdm(
                pool.imap_unordered(process_entry_with_index, enumerate(dataset)),
                total=len(dataset),
                desc="Fuzzing Seeds 多进程进行中"
        ):
            results.append((idx, task_dict))
        pool.close()
        pool.join()

    # 2. 按原始顺序排序
    results.sort(key=lambda x: x[0])
    print("多进程全部结束，正在按原始顺序写入文件...")
    # 3. 一次性顺序写入
    output_path = os.path.join(seed_dir, "fuzz_test_ga.jsonl")
    with open(output_path, 'w', encoding='utf-8') as f:
        for _, task_dict in results:
            json.dump(convert_to_serializable(task_dict), f, ensure_ascii=False)
            f.write("\n")
    print(f"所有种子已按原始数据集顺序保存完成！")
    print(f"保存路径：{os.path.abspath(output_path)}")
    print(f"总计保存 {len(results)} 条记录")
