import copy
import json
import multiprocessing
import os
import random
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


class AntColonyFuzzer:
    def __init__(self, cwe_id: str, code: str, seed_inputs: List[Dict[str, Any]],
                 population_size: int = 20, max_generations: int = 12, num_ants: int = 20,
                 evaporation_rate: float = 0.12, top_k_elites: int = 10):
        self.cwe_id = cwe_id
        self.code = code
        self.population_size = population_size
        self.max_generations = max_generations
        self.num_ants = num_ants
        self.evaporation_rate = evaporation_rate
        self.top_k_elites = top_k_elites

        self.pheromone = defaultdict(float)      # 信息素表
        self.coverage_dict = defaultdict(list)   # 输入 → 路径
        self.all_paths = set()
        self.global_best_input = None
        self.global_best_score = -1

        # 初始化种子
        self.seeds = seed_inputs[:]
        while len(self.seeds) < population_size:
            self.seeds.append(copy.deepcopy(random.choice(seed_inputs)))

    def _deposit_pheromone(self, test_input: Dict[str, Any], score: int):
        """在高覆盖输入的结构路径上沉积信息素"""
        def traverse(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key = f"{path}.{k}||{type(v).__name__}"
                    self.pheromone[key] += score * 0.12
                    traverse(v, f"{path}.{k}")
            elif isinstance(obj, list) and obj:
                for i, v in enumerate(obj[:6]):
                    key = f"{path}[{i}]||{type(v).__name__}"
                    self.pheromone[key] += score * 0.08
                    traverse(v, f"{path}[{i}]")

        traverse(test_input)

    def _build_ant(self) -> Dict[str, Any]:
        base = copy.deepcopy(random.choice(self.seeds))

        def guided_mutate(obj, path=""):
            # 70% 概率受信息素引导
            if random.random() < 0.7:
                candidates = [(self.pheromone[k], k) for k in self.pheromone if k.startswith(path)]
                if candidates and random.random() < 0.65:
                    # 信息素越强，越倾向保留原结构（跟随成功路径）
                    return obj

            return mutate_value_rma(obj)

        def recursive_mutate(inputs, path=""):
            mutated = {}
            for k, v in inputs.items():
                new_v = guided_mutate(v, f"{path}.{k}")
                if isinstance(v, dict):
                    mutated[k] = recursive_mutate(new_v, f"{path}.{k}") if random.random() < 0.5 else new_v
                elif isinstance(v, list):
                    mutated[k] = [recursive_mutate(x, f"{path}.{k}") if random.random() < 0.3 and isinstance(x, dict) else guided_mutate(x, f"{path}.{k}[i]") for i, x in enumerate(new_v)]
                else:
                    mutated[k] = new_v
            return mutated

        ant = recursive_mutate(base)
        if random.random() < 0.9:
            ant = mutate_inputs(ant)
        return ant

    def evaluate(self, test_input: Dict[str, Any]):
        key = json.dumps(convert_to_serializable(test_input), sort_keys=True)
        if key in self.coverage_dict:
            path = self.coverage_dict[key]
            return len(path), False, path

        score, is_err, path = evaluate_fitness(self.code, test_input, execute_test_case)
        path = list(path) if isinstance(path, set) else path
        self.coverage_dict[key] = path
        self.all_paths.add(tuple(path))
        return len(path), is_err, path

    def run(self) -> List[Dict[str, Any]]:
        print(f"\n{'='*20} ACO 蚁群模糊测试启动 [{self.cwe_id}] {'='*20}")
        print(f"种群={len(self.seeds)}  蚂蚁/代={self.num_ants}  最大代数={self.max_generations}")

        # 初始评估
        for seed in self.seeds:
            score, _, _ = self.evaluate(seed)
            if score > self.global_best_score:
                self.global_best_score = score
                self.global_best_input = copy.deepcopy(seed)

        for gen in range(1, self.max_generations + 1):
            print(f"\n--- 第 {gen}/{self.max_generations} 代 投放 {self.num_ants} 只蚂蚁 ---")
            ants_this_gen = []

            for i in range(self.num_ants):
                ant_input = self._build_ant()
                score, crash, _ = self.evaluate(ant_input)
                ants_this_gen.append((score, ant_input, crash))

                print(f"  蚂蚁 {i:2d} → 路径覆盖 {score:3d}  crash={crash}")

                if score > self.global_best_score:
                    self.global_best_score = score
                    self.global_best_input = copy.deepcopy(ant_input)
                    print(f"  >>> 发现全局最优！路径数 = {self.global_best_score}")

            # 精英沉积信息素
            ants_this_gen.sort(key=lambda x: x[0], reverse=True)
            for score, inp, _ in ants_this_gen[:self.top_k_elites]:
                self._deposit_pheromone(inp, score)

            # 信息素蒸发
            for k in list(self.pheromone.keys()):
                self.pheromone[k] *= (1 - self.evaporation_rate)

            print(f"第 {gen} 代结束 | 全局最佳: {self.global_best_score} | 累计路径: {len(self.all_paths)}")

        # 返回去重后的 Top10
        seen = set()
        result = []
        for score, inp, _ in sorted(ants_this_gen, key=lambda x: x[0], reverse=True):
            key = json.dumps(convert_to_serializable(inp), sort_keys=True)
            path_t = tuple(self.coverage_dict[key])
            if path_t not in seen:
                seen.add(path_t)
                result.append(inp)
                if len(result) >= 10:
                    break

        if self.global_best_input and len(result) < 10:
            gpath = tuple(self.coverage_dict[json.dumps(convert_to_serializable(self.global_best_input), sort_keys=True)])
            if gpath not in seen:
                result.append(self.global_best_input)

        print(f"\n=== [{self.cwe_id}] ACO 结束 === 累计发现 {len(self.all_paths)} 条路径，返回 {len(result)} 个最优种子")
        return result[:10]


def aco_fuzz(cwe_id: str, seed_inputs: List[Dict[str, Any]], code: str) -> List[Dict[str, Any]]:
    fuzzer = AntColonyFuzzer(
        cwe_id=cwe_id,
        code=code,
        seed_inputs=seed_inputs,
        population_size=10,
        max_generations=4,
        num_ants=10,
        top_k_elites=6
    )
    return fuzzer.run()


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
        task = {'ID': cwe_id, "code": code, "fuzzing_test_status": "function does not load"}
    elif status == 2:
        task = {'ID': cwe_id, "code": code, "fuzzing_inputs": "No inputs created"}
    return task


def create_seed(entry: Dict[str, Any]):
    global func
    code = entry['Insecure_code']
    cwe_id = entry['ID']
    tester_fuzz_agent = TesterFuzzAgent(entry)
    test_inputs_list = []

    try:
        func, func_name, temp_file_path = check_loader_code(code)
    except Exception:
        return save_seed(code, cwe_id, test_inputs_list, 1)

    test_inputs = tester_fuzz_agent.generate_test_inputs()
    test_inputs_list.append(test_inputs)
    if not test_inputs_list:
        return save_seed(code, cwe_id, test_inputs_list, 2)

    test_inputs_list = aco_fuzz(
        cwe_id=cwe_id,
        seed_inputs=test_inputs_list,
        code=code
    )

    print(f"[{cwe_id}] ACO 优化完成，生成 {len(test_inputs_list)} 个高质量种子")
    return save_seed(code, cwe_id, test_inputs_list[:10], 0)


def process_entry_with_index(args: Tuple[int, Dict[str, Any]]):
    idx, entry = args
    try:
        task = create_seed(entry)
        print(f"完成: {entry['ID']}")
        return idx, task
    except Exception as e:
        print(f"错误 {entry['ID']}: {e}")
        return idx, {'ID': entry['ID'], "error": str(e)}


def get_optimal_thread_count():
    cpu = multiprocessing.cpu_count()
    workers = max(1, int(cpu * 0.75))
    print(f"使用 {workers} 个线程")
    return workers


if __name__ == '__main__':
    reliability_guard(maximum_memory_bytes=2 ** 32)
    dataset = load_vulnerability_dataset(
        os.environ.get("VULNERABILITY_DATA_FILE", "vulnerability_data.jsonl")
    )
    print(f"加载 {len(dataset)} 条漏洞数据")

    num_workers = get_optimal_thread_count()
    os.makedirs("seed", exist_ok=True)

    results = []
    with multiprocessing.Pool(processes=num_workers) as pool:
        for idx, task_dict in tqdm(
            pool.imap_unordered(process_entry_with_index, enumerate(dataset)),
            total=len(dataset),
            desc="ACO Fuzzing 多进程进行中"
        ):
            results.append((idx, task_dict))

    results.sort(key=lambda x: x[0])
    output_path = "seed/fuzz_test_aco.jsonl"
    with open(output_path, 'a', encoding='utf-8') as f:
        for _, task in results:
            json.dump(convert_to_serializable(task), f, ensure_ascii=False)
            f.write("\n")
    # 111
    print(f"\n所有任务完成！结果已保存至：{os.path.abspath(output_path)}")