import json
import os
import random
import string
import sys
from typing import Dict, Any, List, Tuple
# 获取根路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
project_root = os.path.dirname(parent_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

from agent.llm_create_seed_agent import TesterFuzzAgent
from fuzz_programmer_test import check_loader_code, execute_test_case, reliability_guard
from utils import convert_to_serializable
from copy import deepcopy




def load_vulnerability_dataset(file_path: str) -> List[Dict[str, Any]]:
    """加载漏洞数据集"""
    dataset = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            dataset.append(json.loads(line))
    return dataset


def mutate_value(value):
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
        return [mutate_value(element) for element in value]
    elif isinstance(value, dict):
        # 通过变异键或值、添加或删除键值对对字典进行变异
        if len(value) == 0:
            return {mutate_value(''): mutate_value('')}  # 如果字典为空，添加一个新的随机键值对
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
        return value  # 对于不支持的类型，原样返回


def mutate_inputs(inputs):
    """对动态`inputs`对象的内容进行变异。"""
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
    """生成模糊输入并使用它们运行函数。"""
    # 提取并变异输入
    return mutate_inputs(inputs)


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
    with open("seed/fuzz_test_1.jsonl", 'a', encoding='utf-8') as f:
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
    # 对于有一些代码LLM指导生成不了测试用例，采用兜底方案，确保条件变量初始种子一致。
    if not test_inputs_list:
        test_inputs = tester_fuzz_agent.generate_test_inputs()  # 生成初始种子
        for iteration in range(10):
            mutate_inputs = fuzz_function(test_inputs, code)
            test_inputs_list.append(mutate_inputs)
    if not test_inputs_list:
        save_seed(code, cve_id, test_inputs_list, 2)
        return

    print(f"条目 {cve_id} 变异后测试用例数量: {len(test_inputs_list)}")
    test_inputs_list = test_inputs_list[:10]
    save_seed(code, cve_id, test_inputs_list, 0)
    print(f"条目 {cve_id} 任务已保存")


if __name__ == '__main__':
    reliability_guard(maximum_memory_bytes=2 ** 30)
    dataset = load_vulnerability_dataset("vulnerability_data.jsonl")
    for entry in dataset:
        create_seed(entry)
