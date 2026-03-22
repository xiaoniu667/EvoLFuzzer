# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
按顺序执行 crash 目录下所有 create_seed_*.py 种子生成脚本。
"""

import os
import subprocess
import sys
from pathlib import Path

# Project root directory
ROOT = Path(__file__).resolve().parent.parent

# crash 目录
CRASH_DIR = ROOT / "crash"


def get_seed_scripts():
    """获取 crash 目录下所有 create_seed_*.py 脚本"""
    scripts = []
    for f in sorted(CRASH_DIR.glob("create_seed_*.py")):
        scripts.append(f)
    return scripts


def print_banner():
    print("\n" + "="*60)
    print("  批量执行种子生成脚本")
    print("="*60)


def run_script(script_path: Path, dataset_path: Path) -> bool:
    """运行单个脚本"""
    print(f"\n>>> 正在运行: {script_path.name}")

    command = [sys.executable, str(script_path)]
    env = os.environ.copy()
    env["VULNERABILITY_DATA_FILE"] = str(dataset_path)

    try:
        result = subprocess.run(command, cwd=ROOT, env=env, check=True)
        print(f"<<< {script_path.name} 执行完成\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f"!!! {script_path.name} 执行失败 (退出码: {e.returncode})\n")
        return False


def main():
    print_banner()

    # 获取数据集路径（默认在 crash/ 目录下）
    default_dataset = CRASH_DIR / "vulnerability_data.jsonl"
    dataset_path = Path(os.environ.get("VULNERABILITY_DATA_FILE", str(default_dataset)))
    if not dataset_path.exists():
        print(f"错误: 找不到数据集文件: {dataset_path}")
        return 1

    print(f"数据集: {dataset_path}")

    # 获取所有种子生成脚本
    scripts = get_seed_scripts()
    if not scripts:
        print("错误: crash 目录下没有找到 create_seed_*.py 文件")
        return 1

    print(f"找到 {len(scripts)} 个脚本:")
    for s in scripts:
        print(f"  - {s.name}")
    print()

    # 依次执行
    results = {}
    for script in scripts:
        success = run_script(script, dataset_path)
        results[script.name] = success

    # 打印总结
    print("="*60)
    print("执行总结:")
    success_count = sum(1 for v in results.values() if v)
    for name, success in results.items():
        status = "✅" if success else "❌"
        print(f"  {status} {name}")

    print(f"\n成功: {success_count}/{len(results)}")
    print("="*60)

    return 0 if success_count == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
