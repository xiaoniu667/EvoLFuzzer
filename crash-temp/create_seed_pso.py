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


def mutate_value_rma(value):
    """根据值的类型对单个值进行变异。"""
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
        return value


def mutate_inputs(inputs):
    """对动态 inputs 对象的内容进行变异"""
    mutated_inputs = {}
    try:
        for key, value in inputs.items():
            mutated_inputs[key] = mutate_value_rma(copy.deepcopy(value))
    except AttributeError:
        if isinstance(inputs, list):
            inputs = {i: item for i, item in enumerate(inputs)}
        for key, value in inputs.items():
            mutated_inputs[key] = mutate_value_rma(copy.deepcopy(value))
    return mutated_inputs


def sanitize_input(data):
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
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_to_float(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_float(v) for v in obj]
    return obj


def evaluate_fitness(code, test_input):
    try:
        test_input_converted = convert_to_float(test_input)
        score, is_error, branches = execute_test_case(code, test_input_converted)
        branches = list(branches) if isinstance(branches, set) else branches
        return score, is_error, branches
    except Exception as e:
        print("适应度评估失败: {}".format(str(e)))
        return 0.0, False, []


def uniform_crossover(parent1, parent2):
    child = copy.deepcopy(parent1)
    for key in parent1:
        if key in parent2 and random.random() < 0.5:
            child[key] = copy.deepcopy(parent2[key])
    return child


# ====================== 纯离散 PSO======================
def pso_fuzz_discrete(cwe_id, seed_inputs, code,
                       swarm_size=10, max_iterations=4,
                       mutation_rate=0.35, pbest_influence=0.5, gbest_influence=0.7):
    """
    公平版 PSO：执行与 EvoLFuzzer 相同的 TOTAL_BUDGET 次测试，
    只有发现新路径的测试用例才会被保存。
    """
    print("\n=== [{}] PSO 模糊测试 (Budget={}, swarm={}, iter={}) ===".format(
        cwe_id, TOTAL_BUDGET, swarm_size, max_iterations))

    # 初始化粒子群
    swarm = []
    for seed in seed_inputs:
        swarm.append({"position": copy.deepcopy(seed), "pbest": copy.deepcopy(seed), "pbest_score": -1})
    while len(swarm) < swarm_size:
        swarm.append({"position": copy.deepcopy(random.choice(seed_inputs)),
                      "pbest": copy.deepcopy(random.choice(seed_inputs)), "pbest_score": -1})

    gbest = None
    gbest_score = -1
    coverage_dict = defaultdict(list)
    all_paths = set()
    new_path_inputs = []

    def evaluate(ind):
        key = json.dumps(convert_to_serializable(ind), sort_keys=True)
        if key in coverage_dict:
            path = coverage_dict[key]
            return len(path), False, path
        score, is_err, path = evaluate_fitness(code, ind, execute_test_case)
        path = list(path) if isinstance(path, set) else path
        coverage_dict[key] = path
        path_tuple = tuple(path)
        if path_tuple not in all_paths:
            all_paths.add(path_tuple)
            new_path_inputs.append(copy.deepcopy(ind))
        return len(path), is_err, path

    # 初始评估
    for i, p in enumerate(swarm):
        score, is_err, path = evaluate(p["position"])
        p["pbest_score"] = score
        p["pbest"] = copy.deepcopy(p["position"])
        print("  粒子 {}: 路径长度={:3d}, crash={}".format(i, score, is_err))
        if score > gbest_score:
            gbest_score = score
            gbest = copy.deepcopy(p["position"])

    print("  初始评估结束: 发现 {} 条路径, 保存 {} 个测试用例".format(len(all_paths), len(new_path_inputs)))

    # 主循环
    for it in range(1, max_iterations + 1):
        print("\n--- 第 {}/{} 代 ---".format(it, max_iterations))
        for i, particle in enumerate(swarm):
            pos = particle["position"]
            new_pos = copy.deepcopy(pos)

            # 认知学习：向 pbest 交叉
            if random.random() < pbest_influence:
                new_pos = uniform_crossover(new_pos, particle["pbest"])

            # 社会学习：向 gbest 交叉
            if random.random() < gbest_influence and gbest is not None:
                new_pos = uniform_crossover(new_pos, gbest)

            # 核心变异
            if random.random() < mutation_rate:
                new_pos = mutate_inputs(new_pos)

            # 小概率彻底随机变异，防止早熟
            if random.random() < 0.05:
                new_pos = mutate_inputs(new_pos)

            particle["position"] = new_pos

            # 评估新位置
            score, is_err, path = evaluate(new_pos)
            print("  粒子 {}: 路径长度={:3d}, crash={}".format(i, score, is_err))

            # 更新个体最优
            if score > particle["pbest_score"]:
                particle["pbest_score"] = score
                particle["pbest"] = copy.deepcopy(new_pos)

            # 更新全局最优
            if score > gbest_score:
                gbest_score = score
                gbest = copy.deepcopy(new_pos)
                print("    >>> 发现全局新最优！路径数 = {}".format(gbest_score))

        print("第 {} 代结束: 全局最佳={:3d} | 累计路径={:3d} | 保存测试用例={}".format(
            it, gbest_score, len(all_paths), len(new_path_inputs)))

    # 返回新路径测试用例（最多10个）
    result = new_path_inputs[:10]
    print("\n=== [{}] PSO 结束 ===".format(cwe_id))
    print("  总执行次数: {} | 发现路径数: {} | 保存测试用例数: {}".format(
        TOTAL_BUDGET, len(all_paths), len(result)))
    return result


def load_vulnerability_dataset(file_path):
    dataset = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            dataset.append(json.loads(line))
    return dataset


def save_seed(code, cwe_id, test_inputs_list=None, status=0):
    if status == 0:
        return {'ID': cwe_id, "code": code, "fuzzing_inputs": test_inputs_list}
    elif status == 1:
        print("条目 {} 未能正常加载函数".format(cwe_id))
        return {'ID': cwe_id, "code": code, "fuzzing_test_status": "function does not load"}
    elif status == 2:
        print("条目 {} 未生成有效测试用例".format(cwe_id))
        return {'ID': cwe_id, "code": code, "fuzzing_inputs": "No inputs created"}


def create_seed(entry):
    code = entry['Insecure_code']
    cwe_id = entry['ID']
    tester_fuzz_agent = TesterFuzzAgent(entry)
    test_inputs_list = []

    try:
        func, func_name, temp_file_path = check_loader_code(code)
    except Exception as e:
        return save_seed(code, cwe_id, test_inputs_list, 1)

    test_inputs = tester_fuzz_agent.generate_test_inputs()
    test_inputs_list.append(test_inputs)

    if not test_inputs_list:
        return save_seed(code, cwe_id, test_inputs_list, 2)

    test_inputs_list = pso_fuzz_discrete(
        cwe_id=cwe_id,
        seed_inputs=test_inputs_list,
        code=code,
        swarm_size=10,
        max_iterations=4,
        mutation_rate=0.35,
        pbest_influence=0.5,
        gbest_influence=0.7
    )

    print("条目 {} PSO 优化后测试用例数量: {}".format(cwe_id, len(test_inputs_list)))
    test_inputs_list = test_inputs_list[:10]
    return save_seed(code, cwe_id, test_inputs_list, 0)


def process_entry_with_index(args):
    idx, entry = args
    try:
        task = create_seed(entry)
        print("条目 {} 处理完成".format(entry['ID']))
        return idx, task
    except Exception as e:
        print("处理 {} 时发生未捕获错误: {}".format(entry['ID'], e))
        return idx, {'ID': entry['ID'], "code": entry.get('Insecure_code', ''), "error": str(e)}


def get_optimal_thread_count():
    cpu = multiprocessing.cpu_count()
    workers = max(1, int(cpu * 0.75))
    print("使用 {} 个线程".format(workers))
    return workers


if __name__ == '__main__':
    multiprocessing.freeze_support()

    reliability_guard(maximum_memory_bytes=2 ** 32)
    dataset = load_vulnerability_dataset(
        os.environ.get("VULNERABILITY_DATA_FILE", "vulnerability_data.jsonl")
    )
    print("加载 {} 条漏洞数据".format(len(dataset)))
    print("PSO 统一预算: swarm={} + {}代×{}粒子 = {} 次执行".format(10, 4, 10, TOTAL_BUDGET))

    num_workers = get_optimal_thread_count()
    crash_dir = os.path.dirname(os.path.abspath(__file__))
    seed_dir = os.path.join(crash_dir, "seed")
    os.makedirs(seed_dir, exist_ok=True)

    results = []
    with multiprocessing.Pool(processes=num_workers) as pool:
        for idx, task_dict in tqdm(
            pool.imap_unordered(process_entry_with_index, enumerate(dataset)),
            total=len(dataset),
            desc="PSO Fuzzing 多进程进行中"
        ):
            results.append((idx, task_dict))

    results.sort(key=lambda x: x[0])
    output_path = os.path.join(seed_dir, "fuzz_test_pso.jsonl")
    with open(output_path, 'a', encoding='utf-8') as f:
        for _, task_dict in results:
            json.dump(convert_to_serializable(task_dict), f, ensure_ascii=False)
            f.write("\n")

    print("\n所有任务完成！结果已保存至：{}".format(os.path.abspath(output_path)))
