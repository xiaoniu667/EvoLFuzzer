import json

import demjson3

from llm_utils import call_chatgpt_fuzzing_tester, generate_test_inputs_cve, generate_test_inputs_cve_40, \
    generate_test_inputs_cve_20, generate_test_inputs_cve_5


def remove_json_prefix(input_str):
    # Check if the input string starts with "json\n"
    if input_str.startswith("json\n"):
        # Remove the prefix and return the remaining string
        return input_str[len("json\n"):]
    return input_str


def clean_json_string(json_string: str) -> str:
    """
    清理JSON字符串，确保格式正确

    Args:
        json_string: 原始JSON字符串

    Returns:
        清理后的JSON字符串
    """

    # 移除多余的空白字符
    json_string = json_string.strip()

    # 处理可能的编码问题
    if isinstance(json_string, bytes):
        json_string = json_string.decode('utf-8')

    # 移除BOM标记
    if json_string.startswith('\ufeff'):
        json_string = json_string[1:]

    # 确保字符串以正确的括号开始和结束
    if not json_string.startswith('[') and not json_string.startswith('{'):
        # 如果不是有效的JSON开始，尝试修复
        json_string = json_string.strip()

    return json_string


class TesterFuzzAgent:
    def __init__(self, entry):
        self.entry = entry

    def generate_test_inputs(self):
        prompt = self.entry['Insecure_code']
        result = False
        for i in range(1):
            inputs = call_chatgpt_fuzzing_tester(prompt)
            # 如果inputs为空，则继续生成
            if not inputs:
                continue
            inputs = remove_json_prefix(inputs)
            inputs = clean_json_string(inputs)
            try:
                json_inputs = json.loads(inputs)
                result = True
                break
            except:
                continue

        if result:
            return json_inputs
        else:
            return {}

    def generate_test_inputs_cve(self, cve_id):
        prompt = self.entry['Insecure_code']
        inputs = generate_test_inputs_cve(prompt, cve_id)
        inputs = remove_json_prefix(inputs)
        inputs = clean_json_string(inputs)
        try:
            json_list = demjson3.decode(inputs)
            return json_list
        except Exception as e:
            return []

    def generate_test_inputs_cve_5(self, cve_id):
        prompt = self.entry['Insecure_code']
        inputs = generate_test_inputs_cve_5(prompt, cve_id)
        inputs = remove_json_prefix(inputs)
        inputs = clean_json_string(inputs)
        try:
            json_list = demjson3.decode(inputs)
            return json_list
        except Exception as e:
            return []

    def generate_test_inputs_cve_20(self, cve_id):
        prompt = self.entry['Insecure_code']
        inputs = generate_test_inputs_cve_20(prompt, cve_id)
        inputs = remove_json_prefix(inputs)
        inputs = clean_json_string(inputs)
        try:
            json_list = demjson3.decode(inputs)
            return json_list
        except Exception as e:
            return []

    def generate_test_inputs_cve_40(self, cve_id):
        prompt = self.entry['Insecure_code']
        inputs = generate_test_inputs_cve_40(prompt, cve_id)
        inputs = remove_json_prefix(inputs)
        inputs = clean_json_string(inputs)
        try:
            json_list = demjson3.decode(inputs)
            return json_list
        except Exception as e:
            return []
