import copy
import json
import os
import random
import re
import sys
import time
import multiprocessing
from collections import defaultdict
from decimal import Decimal
from typing import Dict, Any, List, Tuple
from tqdm import tqdm

# 获取根路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
project_root = os.path.dirname(parent_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

from agent.llm_create_seed_agent import TesterFuzzAgent
from fuzz_programmer_test_muti import check_loader_code, execute_test_case, reliability_guard
from utils import convert_to_serializable


def load_vulnerability_dataset(file_path: str) -> List[Dict[str, Any]]:
    """加载漏洞数据集"""
    dataset = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            dataset.append(json.loads(line))
    return dataset


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


def evaluate_fitness(code: str, test_input: Dict[str, Any], execute_test_case) -> Tuple[float, bool, List[int]]:
    """评估适应度，返回分数、是否崩溃和分支覆盖"""
    try:
        # 将 test_input 中的 Decimal 转换为 float
        test_input_converted = convert_to_float(test_input)
        score, is_error, branches = execute_test_case(code, test_input_converted)
        # 确保 branches 是 list 类型
        branches = list(branches) if isinstance(branches, set) else branches
        return score, is_error, branches
    except Exception as e:
        print(f"适应度评估失败: {str(e)}")
        return 0.0, False, []


def convert_to_float(obj: Any) -> Any:
    """递归将 Decimal 转换为 float"""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {key: convert_to_float(value) for key, value in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_float(item) for item in obj]
    return obj


def crossover(parent1: Dict[str, Any], parent2: Dict[str, Any]) -> Dict[str, Any]:
    """改进交叉操作，增加随机扰动以提高多样性"""
    child = copy.deepcopy(parent1)
    for key in parent1:
        if key in parent2 and random.random() < 0.5:
            value1, value2 = parent1[key], parent2[key]
            # 将 Decimal 转换为 float
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


def mutate(test_input: Dict[str, Any], mutation_rate: float = 0.2) -> Dict[str, Any]:
    """改进变异操作，增加变异率和策略"""
    mutated = copy.deepcopy(test_input)
    for key in mutated:
        mutated[key] = mutate_value(mutated[key], mutation_rate)
    return mutated


def filter_duplicate_results(population: List[Dict[str, Any]], coverage_dict: defaultdict) -> List[Dict[str, Any]]:
    """去重测试用例，保留覆盖不同路径的测试用例"""
    seen_paths = set()
    unique_population = []
    for test_input in population:
        input_key = json.dumps(convert_to_serializable(test_input), sort_keys=True)
        path = tuple(coverage_dict[input_key])  # 转换为tuple以保留路径顺序
        if path not in seen_paths:
            seen_paths.add(path)
            unique_population.append(test_input)
    return unique_population


def ea_fuzz(cwe_id, test_inputs: List[Dict[str, Any]], code: str, population_size: int = 10, generations: int = 4) -> \
        List[Dict[str, Any]]:
    """进化算法优化测试用例，尽量覆盖全路径，以路径为单位记录覆盖"""
    # 初始化种群
    population = test_inputs[:population_size] if len(test_inputs) >= population_size else test_inputs
    coverage_dict = defaultdict(list)  # 记录每个输入的路径（有序分支列表）
    all_paths = set()  # 记录所有发现的路径（以tuple存储）

    # 评估初始种群的适应度
    print("评估初始种群：")
    for test_input in population:
        input_key = json.dumps(convert_to_serializable(test_input), sort_keys=True)
        score, is_error, path = evaluate_fitness(code, test_input, execute_test_case)
        coverage_dict[input_key] = path
        all_paths.add(tuple(path))  # 转换为tuple以保留路径顺序
        print(f"测试种子: {json.dumps(convert_to_serializable(test_input), indent=2, ensure_ascii=False)}")
        print(f"score: {score}, is_error: {is_error}, path: {path}")

    # 统计初始种群的路径覆盖数量
    initial_path_count = len(all_paths)
    initial_path = list(all_paths)
    # print(f"初始种群路径覆盖数量: {initial_path_count}")
    # print(f"初始种群覆盖的路径: {list(all_paths)}")

    # 去重初始种群，保留覆盖不同路径的测试用例
    population = filter_duplicate_results(population, coverage_dict)

    # 进化迭代
    for generation in range(generations):
        print(f"\nGeneration {generation + 1}/{generations}")
        new_population = []
        new_coverage_dict = defaultdict(list)
        # 保留当前种群
        new_population.extend(population)
        new_coverage_dict.update(coverage_dict)

        # 生成新个体（通过交叉和变异）
        while len(new_population) < population_size * 2:  # 生成双倍数量的候选个体
            if len(population) >= 2:
                parent1, parent2 = random.sample(population, 2)
                child = crossover(parent1, parent2)
            else:
                child = copy.deepcopy(random.choice(population))
            child = mutate(child, mutation_rate=0.2)
            new_population.append(child)

        # 评估新种群的适应度
        print("评估新种群：")
        for test_input in new_population:
            input_key = json.dumps(convert_to_serializable(test_input), sort_keys=True)
            if input_key not in new_coverage_dict:
                score, is_error, path = evaluate_fitness(code, test_input, execute_test_case)
                new_coverage_dict[input_key] = path
                all_paths.add(tuple(path))
                print(f"测试种子: {json.dumps(convert_to_serializable(test_input), indent=2, ensure_ascii=False)}")
                print(f"score: {score}, is_error: {is_error}, path: {path}")

        # 去重并选择覆盖率最高的个体
        unique_population = filter_duplicate_results(new_population, new_coverage_dict)
        population = []
        coverage_dict = defaultdict(list)
        sorted_population = sorted(
            unique_population,
            key=lambda x: len(new_coverage_dict[json.dumps(convert_to_serializable(x), sort_keys=True)]),
            reverse=True
        )

        # 选择覆盖率最高的个体，直到达到种群大小或无新路径
        for test_input in sorted_population:
            input_key = json.dumps(convert_to_serializable(test_input), sort_keys=True)
            path = new_coverage_dict[input_key]
            if len(population) < population_size:
                population.append(test_input)
                coverage_dict[input_key] = path
            elif any(tuple(path) not in all_paths for path in [path]):  # 检查是否覆盖新路径
                population.append(test_input)
                coverage_dict[input_key] = path
                all_paths.add(tuple(path))

        print(
            f"Generation {generation + 1} - Population size: {len(population)}, Total paths covered: {len(all_paths)}")

    print(f"编号: {cwe_id}")
    print(f"初始种群路径覆盖数量: {initial_path_count}")
    print(f"初始种群覆盖的路径: {list(initial_path)}")
    print("进化算法最终覆盖的路径：")
    print(f"总路径覆盖数量: {len(all_paths)}")
    print(f"覆盖的路径列表: {list(all_paths)}")
    return population


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
    return convert_to_serializable(task)

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
    # 使用LLM指导的种子生成
    llm_seeds = tester_fuzz_agent.generate_test_inputs_cve_5(cwe_id)
    test_inputs_list.extend(llm_seeds)
    if not test_inputs_list:
        test_inputs = tester_fuzz_agent.generate_test_inputs()  # 生成初始种子
        test_inputs_list.append(test_inputs)
    if not test_inputs_list:
        task = save_seed(code, cwe_id, test_inputs_list, 2)
        return task
    # 使用进化算法优化
    test_inputs_list = ea_fuzz(cwe_id, test_inputs_list, code, population_size=40, generations=8)

    print(f"条目 {cwe_id} 变异后测试用例数量: {len(test_inputs_list)}")
    test_inputs_list = test_inputs_list[:40]
    task = save_seed(code, cwe_id, test_inputs_list, 0)
    return convert_to_serializable(task)


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
        return idx, convert_to_serializable({
            'ID': entry['ID'],
            "code": entry.get('Insecure_code', ''),
            "error": f"unexpected error: {str(e)}"
        })

if __name__ == '__main__':
    start_time = time.time()
    print(f"[INFO] Program started at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")

    reliability_guard(maximum_memory_bytes=2 ** 30)

    dataset = load_vulnerability_dataset("vulnerability_data.jsonl")
    print(f"总共加载了 {len(dataset)} 条数据")

    num_workers = get_optimal_thread_count(factor=0.75)

    # 创建输出目录
    os.makedirs("seed", exist_ok=True)

    # 1. 并行处理（使用 imap_unordered 更快）
    results = []
    with multiprocessing.Pool(processes=num_workers) as pool:
        # enumerate 给每条数据加上原始顺序索引
        for idx, task_dict in tqdm(
                pool.imap_unordered(process_entry_with_index, enumerate(dataset)),
                total=len(dataset),
                desc="Fuzzing Seeds 多进程进行中"
        ):
            results.append((idx, task_dict))

    # 2. 按原始顺序排序
    results.sort(key=lambda x: x[0])
    print("多进程全部结束，正在按原始顺序写入文件...")

    # 3. 一次性顺序写入
    output_path = "seed/seed40_gen8.jsonl"
    with open(output_path, 'a', encoding='utf-8') as f:
        for _, task_dict in results:
            json.dump(convert_to_serializable(task_dict), f, ensure_ascii=False)
            f.write("\n")

    print(f"所有种子已按原始数据集顺序保存完成！")
    print(f"保存路径：{os.path.abspath(output_path)}")
    print(f"总计保存 {len(results)} 条记录")

    # 记录结束时间
    end_time = time.time()
    # 存储到日志文件中
    print(f"[INFO] Program finished at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}")
    print(f"[INFO] Total execution time: {end_time - start_time:.2f} seconds")
    with open("run_log.txt", "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}  ->  "
                f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}  "
                f"耗时 {end_time - start_time:.2f}s  "
                f"处理 {len(dataset)} 条\n")

    print(f"[INFO] Done! 耗时 {end_time - start_time:.2f}s")