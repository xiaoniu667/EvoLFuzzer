import copy
import json
import random
import re
from collections import defaultdict
from decimal import Decimal
from typing import Dict, Any, List, Tuple

from agent.llm_create_seed_agent import TesterFuzzAgent
from fuzz_programmer_test import check_loader_code, execute_test_case, reliability_guard
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


def ea_fuzz(cve_id, test_inputs: List[Dict[str, Any]], code: str, population_size: int = 10, generations: int = 4) -> \
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

    print(f"编号: {cve_id}")
    print(f"初始种群路径覆盖数量: {initial_path_count}")
    print(f"初始种群覆盖的路径: {list(initial_path)}")
    print("进化算法最终覆盖的路径：")
    print(f"总路径覆盖数量: {len(all_paths)}")
    print(f"覆盖的路径列表: {list(all_paths)}")
    return population


def save_seed(code: str, cve_id: str, test_inputs_list: List[Dict[str, Any]] = None, status: int = 0):
    """保存测试用例到文件"""
    if status == 0:
        task = {
            'ID': cve_id,
            "code": code,
            "fuzzing_inputs": test_inputs_list
        }
    elif status == 1:
        print(f"条目 {cve_id} 未能正常加载函数")
        task = {
            'ID': cve_id,
            "code": code,
            "fuzzing_test_status": "function does not load"
        }
    elif status == 2:
        print(f"条目 {cve_id} 未生成有效测试用例")
        task = {
            'ID': cve_id,
            "code": code,
            "fuzzing_inputs": "No inputs created"
        }
    with open("seed/fuzz_test_6.jsonl", 'a', encoding='utf-8') as f:
        json.dump(convert_to_serializable(task), f, ensure_ascii=False)
        f.write("\n")


def create_seed(entry: Dict[str, Any]):
    """处理单个漏洞条目，生成并优化种子"""
    global func
    code = entry['Insecure_code']
    cve_id = entry['ID']
    tester_fuzz_agent = TesterFuzzAgent(entry)
    test_inputs_list = []
    try:
        func, func_name, temp_file_path = check_loader_code(code)  # 检查并加载代码
    except Exception as e:
        save_seed(code, cve_id, test_inputs_list, 1)
        return
    # 使用LLM指导的种子生成
    llm_seeds = tester_fuzz_agent.generate_test_inputs_cve(cve_id)
    test_inputs_list.extend(llm_seeds)
    if not test_inputs_list:
        test_inputs = tester_fuzz_agent.generate_test_inputs()  # 生成初始种子
        test_inputs_list.append(test_inputs)
    if not test_inputs_list:
        save_seed(code, cve_id, test_inputs_list, 2)
        return
    # 使用进化算法优化
    test_inputs_list = ea_fuzz(cve_id, test_inputs_list, code, population_size=10, generations=4)
    print(f"条目 {cve_id} 变异后测试用例数量: {len(test_inputs_list)}")
    test_inputs_list = test_inputs_list[:10]
    save_seed(code, cve_id, test_inputs_list, 0)
    print(f"条目 {cve_id} 任务已保存")


if __name__ == '__main__':
    reliability_guard(maximum_memory_bytes=2 ** 30)
    dataset = load_vulnerability_dataset("vulnerability_data.jsonl")
    for entry in dataset:
        create_seed(entry)
