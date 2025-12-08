import copy
import json
import multiprocessing
import os
import random
import re
import string
from collections import defaultdict
from decimal import Decimal
from typing import Dict, Any, List, Tuple

from tqdm import tqdm

from agent.llm_create_seed_agent import TesterFuzzAgent
from fuzz_programmer_test_muti import check_loader_code, execute_test_case, reliability_guard
from utils import convert_to_serializable


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
    """对动态 inputs 对象的内容进行变异（完全使用上面的 mutate_value_rma）"""
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


def sanitize_input(data: Any) -> Any:
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


def convert_to_float(obj: Any) -> Any:
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_to_float(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_float(v) for v in obj]
    return obj


def evaluate_fitness(code: str, test_input: Dict[str, Any], execute_test_case) -> Tuple[float, bool, List[int]]:
    try:
        test_input_converted = convert_to_float(test_input)
        score, is_error, branches = execute_test_case(code, test_input_converted)
        branches = list(branches) if isinstance(branches, set) else branches
        return score, is_error, branches
    except Exception as e:
        print(f"适应度评估失败: {str(e)}")
        return 0.0, False, []


def uniform_crossover(parent1: Dict[str, Any], parent2: Dict[str, Any]) -> Dict[str, Any]:
    child = copy.deepcopy(parent1)
    for key in parent1:
        if key in parent2 and random.random() < 0.5:
            child[key] = copy.deepcopy(parent2[key])
    return child


# ====================== 纯离散 PSO======================
def pso_fuzz_discrete(
    cwe_id: str,
    seed_inputs: List[Dict[str, Any]],
    code: str,
    swarm_size: int = 20,
    max_iterations: int = 15,
    mutation_rate: float = 0.35,
    pbest_influence: float = 0.5,
    gbest_influence: float = 0.7,
) -> List[Dict[str, Any]]:
    print(f"\n=== [{cwe_id}] 开始纯离散 PSO 模糊测试 (swarm={swarm_size}, iter={max_iterations}) ===")

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

    def evaluate(ind: Dict[str, Any]):
        key = json.dumps(convert_to_serializable(ind), sort_keys=True)
        if key in coverage_dict:
            path = coverage_dict[key]
            return len(path), False, path
        score, is_err, path = evaluate_fitness(code, ind, execute_test_case)
        path = list(path) if isinstance(path, set) else path
        coverage_dict[key] = path
        all_paths.add(tuple(path))
        return len(path), is_err, path

    # 初始评估
    for i, p in enumerate(swarm):
        score, is_err, path = evaluate(p["position"])
        p["pbest_score"] = score
        p["pbest"] = copy.deepcopy(p["position"])
        print(f"  初始粒子 {i:2d}: 路径长度={score} crash={is_err}")
        if score > gbest_score:
            gbest_score = score
            gbest = copy.deepcopy(p["position"])

    print(f"  初始全局最优覆盖: {gbest_score}")

    # 主循环
    for it in range(1, max_iterations + 1):
        print(f"\n--- 第 {it}/{max_iterations} 代 ---")
        for i, particle in enumerate(swarm):
            pos = particle["position"]

            # 认知学习：向 pbest 交叉
            if random.random() < pbest_influence:
                pos = uniform_crossover(pos, particle["pbest"])

            # 社会学习：向 gbest 交叉
            if random.random() < gbest_influence and gbest is not None:
                pos = uniform_crossover(pos, gbest)

            # 核心变异（你原来的最强变异！）
            if random.random() < mutation_rate:
                pos = mutate_inputs(pos)

            # 小概率彻底随机变异，防止早熟
            if random.random() < 0.05:
                pos = mutate_inputs(pos)

            particle["position"] = pos

            # 评估新位置
            score, is_err, path = evaluate(pos)
            print(f"  粒子 {i:2d} → 新路径长度={score} crash={is_err}")

            # 更新个体最优
            if score > particle["pbest_score"]:
                particle["pbest_score"] = score
                particle["pbest"] = copy.deepcopy(pos)
                print(f"    → 粒子 {i} 更新了个体最优！")

            # 更新全局最优
            if score > gbest_score:
                gbest_score = score
                gbest = copy.deepcopy(pos)
                print(f"    >>> 发现全局新最优！路径数 = {gbest_score}")

        print(f"第 {it} 代结束 → 全局最佳: {gbest_score} | 累计路径数: {len(all_paths)}")

    # 收集最终结果（去重 + 排序）
    candidates = []
    seen = set()
    for p in swarm:
        key = json.dumps(convert_to_serializable(p["position"]), sort_keys=True)
        path_t = tuple(coverage_dict[key])
        if path_t not in seen:
            seen.add(path_t)
            candidates.append((len(path_t), p["position"]))

    if gbest:
        gkey = json.dumps(convert_to_serializable(gbest), sort_keys=True)
        gpath = tuple(coverage_dict[gkey])
        if gpath not in seen:
            candidates.append((len(gpath), gbest))

    candidates.sort(key=lambda x: x[0], reverse=True)
    result = [inp for _, inp in candidates[:10]]

    print(f"\n=== [{cwe_id}] PSO 结束 === 累计不同路径 {len(all_paths)}，返回前10个最优种子")
    return result


def load_vulnerability_dataset(file_path: str) -> List[Dict[str, Any]]:
    dataset = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            dataset.append(json.loads(line))
    return dataset


def save_seed(code: str, cwe_id: str, test_inputs_list: List[Dict[str, Any]] = None, status: int = 0):
    global task
    if status == 0:
        task = {'ID': cwe_id, "code": code, "fuzzing_inputs": test_inputs_list}
    elif status == 1:
        print(f"条目 {cwe_id} 未能正常加载函数")
        task = {'ID': cwe_id, "code": code, "fuzzing_test_status": "function does not load"}
    elif status == 2:
        print(f"条目 {cwe_id} 未生成有效测试用例")
        task = {'ID': cwe_id, "code": code, "fuzzing_inputs": "No inputs created"}
    return task


# ====================== 单条处理主函数 ======================
def create_seed(entry: Dict[str, Any]):
    global func
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
        swarm_size=20,
        max_iterations=4,
        mutation_rate=0.35,
        pbest_influence=0.5,
        gbest_influence=0.7
    )

    print(f"条目 {cwe_id} PSO 优化后测试用例数量: {len(test_inputs_list)}")
    test_inputs_list = test_inputs_list[:10]
    return save_seed(code, cwe_id, test_inputs_list, 0)


def process_entry_with_index(args: Tuple[int, Dict[str, Any]]):
    idx, entry = args
    try:
        task = create_seed(entry)
        print(f"条目 {entry['ID']} 处理完成")
        return idx, task
    except Exception as e:
        print(f"处理 {entry['ID']} 时发生未捕获错误: {e}")
        return idx, {'ID': entry['ID'], "code": entry.get('Insecure_code', ''), "error": str(e)}


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


# ====================== 主入口 ======================
if __name__ == '__main__':
    reliability_guard(maximum_memory_bytes=2 ** 30)
    dataset = load_vulnerability_dataset(
        os.environ.get("VULNERABILITY_DATA_FILE", "vulnerability_data.jsonl")
    )
    print(f"总共加载了 {len(dataset)} 条数据")

    num_workers = get_optimal_thread_count(factor=0.75)
    os.makedirs("seed", exist_ok=True)

    results = []
    with multiprocessing.Pool(processes=num_workers) as pool:
        for idx, task_dict in tqdm(
            pool.imap_unordered(process_entry_with_index, enumerate(dataset)),
            total=len(dataset),
            desc="PSO Fuzzing 多进程进行中"
        ):
            results.append((idx, task_dict))

    results.sort(key=lambda x: x[0])
    output_path = "seed/fuzz_test_pso.jsonl"
    with open(output_path, 'a', encoding='utf-8') as f:
        for _, task_dict in results:
            json.dump(convert_to_serializable(task_dict), f, ensure_ascii=False)
            f.write("\n")

    print(f"\n所有种子已按原始顺序保存完成！")
    print(f"保存路径：{os.path.abspath(output_path)}")
    print(f"总计保存 {len(results)} 条记录")