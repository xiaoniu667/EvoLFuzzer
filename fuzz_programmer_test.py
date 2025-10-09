import faulthandler
import importlib
import importlib.util
import os
import platform
import signal
import tempfile
from contextlib import contextmanager
from typing import Optional

import coverage


def check_loader_code(code):
    temp_files = []
    # 将代码保存到临时文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
        temp_file.write(code)
        temp_file_path = temp_file.name
        temp_files.append(temp_file_path)

    # 动态导入模块
    spec = importlib.util.spec_from_file_location("temp_module", temp_file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # 获取函数名和函数对象
    func_names = [line.split('(')[0].replace('def ', '').strip()
                  for line in code.splitlines() if line.strip().startswith('def')]

    func_name = func_names[0]
    func = getattr(module, func_name)
    return func,func_name, temp_file_path

class TimeoutException(Exception):
    """自定义超时异常"""
    pass


@contextmanager
def timeout(seconds):
    """上下文管理器，用于设置超时"""

    def signal_handler(signum, frame):
        raise TimeoutException("Test case execution exceeded time")

    # 设置信号处理程序
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)  # 启动定时器
    try:
        yield
    finally:
        signal.alarm(0)  # 取消定时器


def execute_test_case(code, input_dict):
    """执行单个测试用例的辅助函数，返回覆盖率、执行状态和覆盖的行"""
    # 获取函数代码
    fuc, func_name,temp_file_path = check_loader_code(code)
    # 确保使用data_file参数指定覆盖率数据文件
    cov_data_file = os.path.join(os.path.dirname(temp_file_path), '.coverage')
    cov = coverage.Coverage(
        data_file=cov_data_file,
        include=[temp_file_path],
        omit=[]
    )

    coverage_score = 0
    is_pass = False  # 是否执行通过
    covered_lines = set()
    try:
        cov.start()
        # 使用超时上下文管理器执行函数
        with timeout(3):  # 设置 3 秒超时
            fuc(**input_dict)
        is_pass = True
    except TimeoutException:
        is_pass = False
        print(f"执行超时")
    except Exception as e:
        is_pass = False
        print(f"执行异常: {str(e)}")
    finally:
        try:
            cov.stop()
            cov.save()
            data = cov.get_data()
            if data and temp_file_path in data.measured_files():
                line_counts = cov._analyze(temp_file_path).numbers
                total_lines = line_counts.n_statements
                missed_lines = line_counts.n_missing
                if total_lines > 0:
                    coverage_score = 100.0 * (total_lines - missed_lines) / total_lines
                # 获取覆盖的行号
                covered_lines = set(data.lines(temp_file_path)) if data.lines(temp_file_path) else set()
        except Exception as e:
            print(f"Failed to compute coverage: {e}")
    return coverage_score, is_pass, covered_lines


def reliability_guard(maximum_memory_bytes: Optional[int] = None):
    """
    禁用可能干扰测试的破坏性功能，包括 HTTP 请求
    """
    # 现有内存限制代码
    if maximum_memory_bytes is not None:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (maximum_memory_bytes, maximum_memory_bytes))
        resource.setrlimit(resource.RLIMIT_DATA, (maximum_memory_bytes, maximum_memory_bytes))
        if not platform.uname().system == 'Darwin':
            resource.setrlimit(resource.RLIMIT_STACK, (maximum_memory_bytes, maximum_memory_bytes))

    # 禁用 faulthandler
    faulthandler.disable()

    # 设置环境变量
    import os
    os.environ['OMP_NUM_THREADS'] = '1'

    # 禁用系统相关功能
    os.kill = None
    os.system = None
    os.putenv = None
    # 保留 os.remove 和 os.unlink
    os.removedirs = None
    os.rmdir = None
    os.fchdir = None
    os.setuid = None
    os.fork = None
    os.forkpty = None
    os.killpg = None
    os.rename = None
    os.renames = None
    os.truncate = None
    os.replace = None
    os.fchmod = None
    os.fchown = None
    os.chmod = None
    os.chown = None
    os.chroot = None
    os.lchflags = None
    os.lchmod = None
    os.lchown = None

    # 禁用 shutil 相关功能
    import shutil
    shutil.rmtree = None
    shutil.move = None
    shutil.chown = None

    # 禁用 subprocess
    import subprocess
    subprocess.Popen = None

    # 禁用其他模块
    import sys
    sys.modules['ipdb'] = None
    sys.modules['joblib'] = None
    sys.modules['psutil'] = None
    sys.modules['tkinter'] = None


