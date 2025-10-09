
import openai
from openai import OpenAI

openai.api_base = "https://api.deepseek.com/v1"
openai.api_key = 'sk-aa57aa87f359482d80d7bb5ad6ca9ffb'
model = "deepseek-chat"
client = OpenAI(api_key=openai.api_key, base_url=openai.api_base)


prompt_path_fuzz = "./prompts/initial_inputs_prompt.txt"
with open(prompt_path_fuzz, "r") as f:
    construct_few_shot_prompt_fuzz = f.read()

prompt_path_fuzz = "./prompts/create_cwe_inputs_prompt.txt"
with open(prompt_path_fuzz, "r") as f:
    construct_cve_prompt_fuzz_batch = f.read()

prompt_path = "./prompts/coder_agent_prompt.txt"
with open(prompt_path, "r") as f:
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
def generate_test_inputs_cve(code, cve_id):
    try:
        text = f"""
         {construct_cve_prompt_fuzz_batch}

       ## Prompt 2:
        **Code**:
        ```python
        {code}
        ```

        **CVE ID**: {cve_id}
 
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


