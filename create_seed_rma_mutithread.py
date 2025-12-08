import json
import multiprocessing
import os
import random
import string
from copy import deepcopy
from multiprocessing import Pool
from typing import Dict, Any, List, Tuple

from tqdm import tqdm  # 进度条

from agent.llm_create_seed_agent import TesterFuzzAgent
from fuzz_programmer_test_muti import check_loader_code, reliability_guard
from utils import convert_to_serializable


def mutate_value(value):
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
        return [mutate_value(element) for element in value]
    elif isinstance(value, dict):
        if len(value) == 0:
            return {mutate_value(''): mutate_value('')}
        mutation_type = random.choice(['mutate_key', 'mutate_value', 'add', 'remove'])
        if mutation_type == 'mutate_key':
            old_key = random.choice(list(value.keys()))
            new_key = mutate_value(old_key)
            value[new_key] = value.pop(old_key)
        elif mutation_type == 'mutate_value':
            key = random.choice(list(value.keys()))
            value[key] = mutate_value(value[key])
        elif mutation_type == 'add':
            value[mutate_value('')] = mutate_value('')
        elif mutation_type == 'remove' and len(value) > 1:
            key = random.choice(list(value.keys()))
            del value[key]
        return value
    else:
        return value


def mutate_inputs(inputs):
    mutated_inputs = {}
    try:
        for key, value in inputs.items():
            mutated_inputs[key] = mutate_value(deepcopy(value))
    except AttributeError as e:
        print(f"错误: {e}。`inputs`对象不是字典。")
        if isinstance(inputs, list):
            inputs = {i: item for i, item in enumerate(inputs)}
        for key, value in inputs.items():
            mutated_inputs[key] = mutate_value(deepcopy(value))
    return mutated_inputs


def fuzz_function(inputs, code, num_tests=1):
    return mutate_inputs(inputs)


def mutate_inputs_list(inputs):
    mutated_inputs_list = []
    for input_dict in inputs:
        mutated_inputs = {}
        try:
            for key, value in input_dict.items():
                mutated_inputs[key] = mutate_value(deepcopy(value))
            mutated_inputs_list.append(mutated_inputs)
        except AttributeError as e:
            print(f"错误: {e}。")
    return mutated_inputs_list


def load_vulnerability_dataset(file_path: str) -> List[Dict[str, Any]]:
    dataset = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            dataset.append(json.loads(line))
    return dataset



def create_seed_and_return(entry: Dict[str, Any]) -> Dict[str, Any]:
    """处理单条 entry，返回要保存的 task 字典（不再直接写文件）"""
    code = entry['Insecure_code']
    cve_id = entry['ID']
    test_inputs_list = []

    try:
        func = check_loader_code(code)  # 检查并加载代码
    except Exception as e:
        print(f"条目 {cve_id} 未能正常加载函数: {e}")
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
        print(f"条目 {cve_id} 生成初始测试用例失败: {e}")

    if not test_inputs_list or not test_inputs_list[0]:
        return {
            'ID': cve_id,
            "code": code,
            "fuzzing_inputs": "No inputs created"
        }

    # 变异 10 次，最多保留 10 条
    for iteration in range(10):
        try:
            mutate_inputs = fuzz_function(test_inputs, code)
            test_inputs_list.append(mutate_inputs)
        except Exception as e:
            print(f"条目 {cve_id} 第 {iteration+1} 次变异出错: {e}")

    test_inputs_list = test_inputs_list[:10]
    print(f"条目 {cve_id} 变异后测试用例数量: {len(test_inputs_list)}")

    return {
        'ID': cve_id,
        "code": code,
        "fuzzing_inputs": test_inputs_list
    }


def process_entry_with_index(args: Tuple[int, Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
    """
    接收 (index, entry)，返回 (index, task_dict)
    这样即使多进程乱序执行，最后也能按 index 排序恢复原始顺序
    """
    idx, entry = args
    try:
        task = create_seed_and_return(entry)
        print(f"条目 {entry['ID']} 处理完成")
        return idx, task
    except Exception as e:
        print(f"处理 {entry['ID']} 时发生未捕获错误: {e}")
        return idx, {
            'ID': entry['ID'],
            "code": entry.get('Insecure_code', ''),
            "error": f"unexpected error: {str(e)}"
        }


def get_optimal_thread_count(factor=0.8, min_threads=1):
    cpu_count = multiprocessing.cpu_count()
    print(f"你的机器有 {cpu_count} 个 CPU 核心")
    num_workers = max(min_threads, int(cpu_count * factor))
    print(f"为并行处理设置 {num_workers} 个线程")
    return num_workers


if __name__ == '__main__':
    reliability_guard(maximum_memory_bytes=2 ** 30)

    dataset = load_vulnerability_dataset(
        os.environ.get("VULNERABILITY_DATA_FILE", "vulnerability_data.jsonl")
    )
    print(f"总共加载了 {len(dataset)} 条数据")

    num_workers = get_optimal_thread_count(factor=0.75)

    # 创建输出目录
    os.makedirs("seed", exist_ok=True)

    # 1. 并行处理
    results = []
    with Pool(processes=num_workers) as pool:
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
    output_path = "seed/fuzz_test_rma.jsonl"
    with open(output_path, 'a', encoding='utf-8') as f:
        for _, task_dict in results:
            json.dump(convert_to_serializable(task_dict), f, ensure_ascii=False)
            f.write("\n")

    print(f"所有种子已按原始数据集顺序保存完成！")
    print(f"保存路径：{os.path.abspath(output_path)}")
    print(f"总计保存 {len(results)} 条记录")
