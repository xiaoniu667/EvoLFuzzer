import json
import os

from agent.llm_create_code_agent import ProgrammerAgent


def load_dataset(file_path):
    """加载数据集文件"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"错误：找不到文件 {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"错误：文件 {file_path} 不是有效的JSON格式")
        return None


def save_generated_code_to_jsonl(entry_id, code,
                                 output_file):
    """保存生成的代码到JSONL文件"""
    # 创建输出目录
    output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else "."
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 准备JSON数据
    json_data = {
        "ID": entry_id,
        "Insecure_code": code
    }

    try:
        # 追加模式写入JSONL文件
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(json_data, ensure_ascii=False) + '\n')
        print(f"代码已保存到JSONL文件: {output_file}")
        return output_file
    except Exception as e:
        print(f"保存JSONL文件失败: {e}")
        return None


def main():
    """主函数"""
    print("开始处理数据集...")

    # 加载数据集
    dataset_path = "../origin_dataset_prompts/LLMSecEval_only_python.json"
    # 输出文件路径
    output_file = "../origin_dataset_prompts/generated_codes/LLMSecEval_only_python_codes.jsonl"

    json_list = load_dataset(dataset_path)
    if json_list is None:
        return

    print(f"数据集加载成功，共有 {len(json_list)} 条记录")

    # 遍历数据集，只处理Python语言的条目
    for entry in json_list:
        if 'LLM-generated NL Prompt' in entry:
            modified_entry = entry.copy()
            modified_entry['Prompt'] = entry['LLM-generated NL Prompt']
            del modified_entry['LLM-generated NL Prompt']
            entry = modified_entry
            # 创建ProgrammerAgent实例
            programmer_agent = ProgrammerAgent(entry)

            # 生成代码
            code = programmer_agent.write_code()

            # 保存代码到JSONL文件
            filepath = save_generated_code_to_jsonl(
                entry.get('Prompt ID', 'Unknown'),
                code,
                output_file
            )

    # 输出统计信息
    print(f"\n处理完成！")


if __name__ == "__main__":
    main()
