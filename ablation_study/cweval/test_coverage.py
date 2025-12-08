import datetime
import glob
import json
import logging
import os
import sys
from collections import defaultdict
# 配置日志
from typing import List

# 获取根路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
project_root = os.path.dirname(parent_dir)
if project_root not in sys.path:
    sys.path.append(project_root)


from fuzz_programmer_test_muti import reliability_guard, check_loader_code, execute_test_case
from utils import convert_to_serializable



logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('branch_coverage.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def load_test_cases(file_path: str) -> List[dict]:
    """加载测试用例文件"""
    logger.info(f"Executing function: load_test_cases for {file_path}")
    test_cases = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                if line.strip():
                    test_cases.append(json.loads(line))
    except FileNotFoundError:
        logger.error(f"Test case file {file_path} not found.")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {file_path}: {e}")
        return []
    return test_cases


def run_coverage_for_file(input_file, output_dir="results", id_to_paths=defaultdict(set)):
    """为单个输入文件运行分支覆盖测试，统计每个种子和测试代码的分支覆盖数，并保存到txt文件"""
    logger.info(f"Running branch coverage for file: {input_file}")
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.basename(input_file).split('.')[0]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"{base_name}_branch_coverage_{timestamp}.md")
    branch_coverage_file = os.path.join(output_dir, f"{base_name}_branch_coverage_{timestamp}.txt")  # txt文件

    # 加载测试用例
    test_inputs = load_test_cases(input_file)
    logger.info(f"Loaded {len(test_inputs)} test cases from {input_file}")
    if not test_inputs:
        logger.warning(f"No test cases loaded from {input_file}. Skipping.")
        return

    # 跟踪所有临时文件的路径
    temp_files = []

    # 测试用例统计
    total_tests = 0

    # 测试代码分支覆盖统计
    test_code_coverage = 0

    for index, test_case in enumerate(test_inputs):  # 遍历每一个测试用例
        fuzzing_inputs = test_case.get('fuzzing_inputs', [])
        test_code = test_case.get('code', '')
        test_id = test_case.get('ID', f'Unknown_ID_{index + 1:03d}')  # 获取ID，空时用默认值

        total_tests += len(fuzzing_inputs)

        if not isinstance(fuzzing_inputs, list):
            logger.error(f"Test case {test_id} has invalid fuzzing_inputs: {type(fuzzing_inputs)}")
            with open(branch_coverage_file, 'a', encoding='utf-8') as f:
                f.write(f"{index}, {test_id}, {0}\n")
            continue

        try:
            func, func_name, temp_file_path = check_loader_code(test_code)  # 检查并加载代码
            logger.info(f"test case {test_id} Loaded function: {func_name}")
        except Exception as e:  # 没加载成功的函数，记录覆盖率为0
            with open(branch_coverage_file, 'a', encoding='utf-8') as f:
                f.write(f"{index}, {test_id}, {0}\n")
            logger.error(f"Error importing module for test case {test_id}: {e}")
            continue

        coverage_dict = defaultdict(list)  # 记录每个输入的路径（有序分支列表）
        local_paths = set()  # 本地记录当前测试用例的路径

        # 记录当前ID的已有路径（在本次测试用例之前）
        previous_paths = id_to_paths[test_id].copy()

        # 逐个执行测试用例
        for input_idx, input_dict in enumerate(fuzzing_inputs):
            # 将路径存储到set之中
            input_key = json.dumps(convert_to_serializable(input_dict), sort_keys=True)
            coverage_score, is_pass, path = execute_test_case(test_code, input_dict)
            coverage_dict[input_key] = path
            local_paths.add(tuple(path))  # 转换为tuple以保留路径顺序

        # 更新全局ID的路径集合
        id_to_paths[test_id].update(local_paths)

        # 计算新增的分支覆盖路径数
        branch_count = len(id_to_paths[test_id]) - len(previous_paths)  # 当前测试用例新增的路径

        # 保存分支覆盖数据到txt文件
        with open(branch_coverage_file, 'a', encoding='utf-8') as f:
            f.write(f"{index}, {test_id}, {branch_count}\n")

        # 更新总覆盖（累加当前测试用例的本地路径数）
        test_code_coverage += branch_count

    # 记录统计信息
    logger.info(f"File {input_file} statistics:")
    logger.info(f" - 总测试用例数: {total_tests}")
    logger.info(f" - 测试代码分支覆盖: {test_code_coverage}")

    stats_filename = os.path.join(output_dir, f"{base_name}_stats_{timestamp}.txt")
    with open(stats_filename, "w", encoding="utf-8") as stats_file:
        stats_file.write(f"文件名: {input_file}\n")
        stats_file.write(f"总测试用例数: {total_tests}\n")
        stats_file.write(f"测试代码分支覆盖: {test_code_coverage}\n")

    # 清理临时文件
    for temp_file in temp_files:
        try:
            os.remove(temp_file)
        except Exception as e:
            logger.error(f"Error removing temporary file {temp_file}: {e}")

    return {"total_tests": total_tests, "file": os.path.basename(input_file), "test_code_coverage": test_code_coverage}


def batch_run_coverage(input_pattern="seed_temp/*.jsonl", output_dir="results"):
    """批量运行分支覆盖测试"""
    logger.info(f"Starting batch branch coverage run for pattern: {input_pattern}")
    os.makedirs(output_dir, exist_ok=True)
    input_files = glob.glob(input_pattern)
    if not input_files:
        logger.warning(f"No input files found matching pattern: {input_pattern}")
        return
    logger.info(f"Found {len(input_files)} input files: {input_files}")
    for input_file in input_files:
        # 全局ID到路径集合的映射，用于去重
        id_to_paths = defaultdict(set)
        run_coverage_for_file(input_file, output_dir, id_to_paths)


if __name__ == '__main__':
    # 设置内存限制
    reliability_guard(maximum_memory_bytes=2 ** 32)
    logger.info("Starting main execution")
    input_pattern = "seed/*.jsonl"
    output_dir = "results"
    batch_run_coverage(input_pattern, output_dir)
