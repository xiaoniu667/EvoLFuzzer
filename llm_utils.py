import os

import openai
from openai import OpenAI

openai.api_base = "https://api.deepseek.com/v1"
openai.api_key = '' #替换为自己的key
model = "deepseek-chat"
client = OpenAI(api_key=openai.api_key, base_url=openai.api_base)

# 获取当前文件所在的绝对路径
current_dir = os.path.dirname(os.path.abspath(__file__))

# ---------- 读取 initial_inputs_prompt.txt ----------
prompt_path_fuzz = os.path.join(current_dir, "prompts", "initial_inputs_prompt.txt")
with open(prompt_path_fuzz, "r", encoding="utf-8") as f:
    construct_few_shot_prompt_fuzz = f.read()

# ---------- 读取 create_cwe_inputs_prompt.txt ----------
prompt_path_fuzz_cwe = os.path.join(current_dir, "prompts", "create_cwe_inputs_prompt.txt")
with open(prompt_path_fuzz_cwe, "r", encoding="utf-8") as f:
    construct_cve_prompt_fuzz_batch = f.read()

prompt_path_fuzz_cwe = os.path.join(current_dir, "prompts", "create_cwe_inputs_prompt_5.txt")
with open(prompt_path_fuzz_cwe, "r", encoding="utf-8") as f:
    construct_cve_prompt_fuzz_batch_5 = f.read()

prompt_path_fuzz_cwe = os.path.join(current_dir, "prompts", "create_cwe_inputs_prompt_20.txt")
with open(prompt_path_fuzz_cwe, "r", encoding="utf-8") as f:
    construct_cve_prompt_fuzz_batch_20 = f.read()

prompt_path_fuzz_cwe = os.path.join(current_dir, "prompts", "create_cwe_inputs_prompt_40.txt")
with open(prompt_path_fuzz_cwe, "r", encoding="utf-8") as f:
    construct_cve_prompt_fuzz_batch_40 = f.read()

# ---------- 读取 coder_agent_prompt.txt ----------
prompt_path_coder = os.path.join(current_dir, "prompts", "coder_agent_prompt.txt")
with open(prompt_path_coder, "r", encoding="utf-8") as f:
    construct_few_shot_prompt = f.read()

def preprocess_string(input_string, lg):
    if f"```{lg}" in input_string:
        input_string = input_string[input_string.find(f"```{lg}") + len(f"```{lg}"):]
        input_string = input_string[:input_string.find("```")]
    elif "```" in input_string:
        input_string = input_string[input_string.find("```") + 3:]
        input_string = input_string[:input_string.find("```")]

    return input_string

# 生成初始的测试用例
def call_chatgpt_fuzzing_tester(prompt):
    text = f"""
    {construct_few_shot_prompt_fuzz}

    ## Prompt 2:
    ```python
    {prompt}
    ```
    ## Completion 2:
    """
    try:
        completion = client.chat.completions.create(
            model=model,
            stream=False,
            messages=[
                {"role": "system", "content": "You are a code tester specialized in fuzzing."},
                {"role": "user", "content": text},
            ]
        )
        completion = completion.choices[0].message.content.strip()
        completion = preprocess_string(completion, "python")

    except Exception as e:
        print(e)
        completion = ""

    return completion

# LLM指导针对CVE以及漏洞代码生成测试用例
def generate_test_inputs_cve(code, cwe_id):
    try:
        text = f"""
         {construct_cve_prompt_fuzz_batch}

       ## Prompt 2:
        **Code**:
        ```python
        {code}
        ```

        **CVE ID**: {cwe_id}
 
        ## Completion 2:

"""
        completion = client.chat.completions.create(
            model=model,
            stream=False,
            messages=[
                {"role": "system", "content": "You are a code tester specialized in fuzzing."},
                {"role": "user", "content": text},
            ]
        )
        completion = completion.choices[0].message.content.strip()
        completion = preprocess_string(completion, "python")
    except Exception as e:
        print(e)
        completion = ""
    return completion



def generate_test_inputs_cve_5(code, cwe_id):
    try:
        text = f"""
         {construct_cve_prompt_fuzz_batch_5}

       ## Prompt 2:
        **Code**:
        ```python
        {code}
        ```

        **CVE ID**: {cwe_id}
 
        ## Completion 2:

"""
        completion = client.chat.completions.create(
            model=model,
            stream=False,
            messages=[
                {"role": "system", "content": "You are a code tester specialized in fuzzing."},
                {"role": "user", "content": text},
            ]
        )
        completion = completion.choices[0].message.content.strip()
        completion = preprocess_string(completion, "python")
    except Exception as e:
        print(e)
        completion = ""
    return completion


def generate_test_inputs_cve_20(code, cwe_id):
    try:
        text = f"""
         {construct_cve_prompt_fuzz_batch_20}

       ## Prompt 2:
        **Code**:
        ```python
        {code}
        ```

        **CVE ID**: {cwe_id}
 
        ## Completion 2:

"""
        completion = client.chat.completions.create(
            model=model,
            stream=False,
            messages=[
                {"role": "system", "content": "You are a code tester specialized in fuzzing."},
                {"role": "user", "content": text},
            ]
        )
        completion = completion.choices[0].message.content.strip()
        completion = preprocess_string(completion, "python")
    except Exception as e:
        print(e)
        completion = ""
    return completion


def generate_test_inputs_cve_40(code, cwe_id):
    try:
        text = f"""
         {construct_cve_prompt_fuzz_batch_40}

       ## Prompt 2:
        **Code**:
        ```python
        {code}
        ```

        **CVE ID**: {cwe_id}
 
        ## Completion 2:

"""
        completion = client.chat.completions.create(
            model=model,
            stream=False,
            messages=[
                {"role": "system", "content": "You are a code tester specialized in fuzzing."},
                {"role": "user", "content": text},
            ]
        )
        completion = completion.choices[0].message.content.strip()
        completion = preprocess_string(completion, "python")
    except Exception as e:
        print(e)
        completion = ""
    return completion



# 生成代码
def call_chatgpt_programmer(prompt):
    text = f"""
    {construct_few_shot_prompt}

    **Input Code Snippet**:
    ```python
    {prompt}
    ```
    ## Completion 3:
    """
    completions_code = []
    try:
        completion = client.chat.completions.create(
            model=model,
            stream=False,
            messages=[
                {"role": "system", "content": "You are a software programmer."},
                {"role": "user", "content": text},
            ]
        )
        completion = completion.choices[0].message.content.strip()
        completion = preprocess_string(completion, "python")

    except Exception as e:
        print(e)
        completion = ""

    return completion


