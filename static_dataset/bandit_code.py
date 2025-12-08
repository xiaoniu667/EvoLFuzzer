# 加载SecurityEval数据集
# 根据Bandit静态分析工具检测漏洞的个数

import json
import subprocess
import tempfile
import os

def run_bandit_on_code(code):
    """
    使用Bandit分析给定的代码字符串，返回漏洞检测结果。
    """
    # 创建临时文件存储代码
    with tempfile.NamedTemporaryFile(delete=False, suffix='.py') as temp_file:
        temp_file.write(code.encode('utf-8'))
        temp_file_path = temp_file.name

    try:
        # 运行Bandit并以JSON格式输出结果
        result = subprocess.run(
            ['bandit', '-r', temp_file_path, '-f', 'json'],
            capture_output=True,
            text=True
        )

        if result is None:
            return "error", "none type", ""

        if result.returncode == 0:
            return "safe", "0", ""

        if result.returncode == 1:
            bandit_result = json.loads(result.stdout)
            cwe_codes = []
            issue_texts = []
            for issue in bandit_result.get("results", []):
                cwe_id = issue.get("issue_cwe", {}).get("id")
                if cwe_id:
                    cwe_code = f"CWE-{cwe_id}"
                    cwe_codes.append(cwe_code)
                issue_text = issue.get("issue_text", "")
                issue_texts.append(issue_text)

            # 将所有CWE编号和问题描述合并为字符串
            all_cwe_codes = ', '.join(cwe_codes) if cwe_codes else "none"
            all_issue_texts = ' | '.join(issue_texts) if issue_texts else "none"
            return "vulnerable", all_cwe_codes, all_issue_texts
        else:
            return "error", "", result.stderr

    finally:
        # 清理临时文件
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

def process_jsonl(input_file, output_file):
    """
    处理JSONL格式的数据集，运行Bandit分析，统计漏洞数量并保存结果。
    数据集格式示例：
    {"ID": "CWE-020_author_1.py", "Prompt": "...", "Insecure_code": "..."}
    """
    results = {}
    vuln_count = 0  # 漏洞计数器
    total_files = 0  # 总文件计数器

    with open(input_file, 'r') as infile:
        for line in infile:
            entry = json.loads(line)
            code_id = entry['ID']
            code = entry['Insecure_code']
            total_files += 1

            # 运行Bandit分析
            bandit_result, cwe_code, issue_text = run_bandit_on_code(code)

            # 如果发现漏洞，增加计数
            if bandit_result == "vulnerable":
                vuln_count += 1

            # 存储结果
            results[code_id] = {
                "result": bandit_result,
                "cwe_code": cwe_code,
                "issue_text": issue_text
            }

    # 添加统计信息到结果
    results["statistics"] = {
        "total_files_analyzed": total_files,
        "vulnerable_files_count": vuln_count,
        "vulnerability_ratio": vuln_count / total_files if total_files > 0 else 0
    }

    # 打印统计信息
    print(f"Total files analyzed: {total_files}")
    print(f"Vulnerable files found: {vuln_count}")
    print(f"Vulnerability ratio: {vuln_count / total_files:.2%}" if total_files > 0 else "No files analyzed")

    # # 保存结果到输出JSON文件
    # with open(output_file, 'a') as outfile:
    #     json.dump(results, outfile, indent=4)

if __name__ == "__main__":
    process_jsonl('../datasets/SecurityEval.jsonl', '')