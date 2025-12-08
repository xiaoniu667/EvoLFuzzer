import faulthandler
import importlib
import importlib.util
import os
import platform
import signal
import sqlite3
import tempfile
import uuid
from contextlib import contextmanager
from io import BytesIO
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
    """
    根据代码内容自动选择执行方式：
    - 普通 Python: do_execute_test_case
    - Flask Web 应用: do_execute_test_case_web
    """

    code_lower = code.lower()

    is_flask_app = (
        "from flask" in code_lower or
        "flask(" in code_lower or
        "@app.route" in code_lower
    )

    if is_flask_app:
        return do_execute_test_case_web(code, input_dict)
    else:
        return do_execute_test_case(code, input_dict)



def do_execute_test_case(code, input_dict):
    """执行单个测试用例的辅助函数，返回覆盖率、执行状态和覆盖的行"""
    # 获取函数代码
    fuc, func_name,temp_file_path = check_loader_code(code)
    # 确保使用data_file参数指定覆盖率数据文件
    cov_data_file = os.path.join(
        os.path.dirname(temp_file_path),
        f".coverage_{uuid.uuid4().hex}"
    )
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


def do_execute_test_case_web(code, input_dict):
    """
    修正版 execute_test_case_web：
    - 在加载模块前启动 coverage
    - include 使用绝对路径
    - 自动屏蔽 render_template / Jinja2 查找模板
    - 支持 cookies/session/headers/files 等完整 Flask fuzzing
    """

    # 1) 写入临时文件
    _, _, temp_file_path = check_loader_code(code)
    abs_path = os.path.abspath(temp_file_path)

    # 2) 开启 coverage（必须在 import 前）
    cov_data_file = os.path.join(
        os.path.dirname(temp_file_path),
        f".coverage_{uuid.uuid4().hex}"
    )
    cov = coverage.Coverage(data_file=cov_data_file, include=[abs_path])
    cov.start()

    try:
        with timeout(3):
            # 3) 动态导入模块
            spec = importlib.util.spec_from_file_location("temp_module", temp_file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # 4) 找 app，不是 Flask 则退出
            if "app" not in module.__dict__:
                cov.stop()
                cov.save()
                return 0.0, False, set()

            app = module.app

            try:
                from flask import render_template
                import types
                import jinja2

                def fake_render_template(name, **kwargs):
                    return f"[FAKE TEMPLATE: {name}]"

                # 覆盖模块内的 render_template（用于用户代码里调用）
                module.render_template = fake_render_template

                # 覆盖 Flask 内部真正的选择模板逻辑，避免 Jinja2 查文件
                app.jinja_env.get_or_select_template = lambda *a, **k: None

            except Exception as e:

                print("WARNING: Fake template patch failed:", e)


            client = app.test_client()

            # 5) sessions
            if "session" in input_dict:
                with client.session_transaction() as sess:
                    for k, v in input_dict["session"].items():
                        sess[k] = v

            # 6) cookies
            for k, v in input_dict.get("cookies", {}).items():
                client.set_cookie(server_name="localhost", key=k, value=v)

            headers = input_dict.get("headers", {}) or {}
            args = input_dict.get("args", {}) or {}
            form = input_dict.get("form", {}) or {}
            json_body = input_dict.get("json", None)
            raw_data = input_dict.get("data", None)
            values = input_dict.get("values", {}) or {}
            files = input_dict.get("files", {}) or {}

            # 7) 自动选路由
            target_rule = None
            for rule in app.url_map.iter_rules():
                if rule.endpoint == "static":
                    continue
                target_rule = rule
                break

            if target_rule is None:
                raise RuntimeError("No routable endpoint found.")

            route_url = target_rule.rule
            methods = list(target_rule.methods - {"HEAD", "OPTIONS"})

            # path parameters
            if target_rule.arguments:
                for p in target_rule.arguments:
                    val = input_dict.get("path_params", {}).get(p, "1")
                    route_url = route_url.replace(f"<{p}>", str(val))
                    route_url = route_url.replace(f"<int:{p}>", str(val))
                    route_url = route_url.replace(f"<string:{p}>", str(val))

            # 8) method 推断
            method = input_dict.get("method")
            if not method:
                if "POST" in methods and (form or json_body or raw_data or files):
                    method = "POST"
                else:
                    method = "GET"
            method = method.upper()

            send_kwargs = {"query_string": args}
            if headers:
                send_kwargs["headers"] = headers

            # 9) 文件上传
            if files:
                data = {}
                if form:
                    data.update(form)
                for key, finfo in files.items():
                    fname = finfo.get("filename", "file")
                    content = finfo.get("content", b"")
                    if isinstance(content, str):
                        content = content.encode()
                    data[key] = (BytesIO(content), fname)
                send_kwargs["data"] = data

            else:
                if method == "POST":
                    if json_body is not None:
                        send_kwargs["json"] = json_body
                    elif raw_data is not None:
                        send_kwargs["data"] = raw_data
                    elif form:
                        send_kwargs["data"] = form
                    elif values:
                        send_kwargs["data"] = values
                    else:
                        send_kwargs["data"] = {}
                # GET 不需要 data

            # 10) 发请求
            if method == "POST":
                resp = client.post(route_url, **send_kwargs)
            elif method == "PUT":
                resp = client.put(route_url, **send_kwargs)
            elif method == "DELETE":
                resp = client.delete(route_url, **send_kwargs)
            else:
                resp = client.get(route_url, **send_kwargs)

            is_pass = (resp is not None and resp.status_code < 500)

    except TimeoutException:
        print("执行超时")
        try:
            cov.stop()
            cov.save()
        except:
            pass
        return 0.0, False, set()

    except Exception as e:
        print("执行异常:", repr(e))
        try:
            cov.stop()
            cov.save()
        except:
            pass
        return 0.0, False, set()

    # 11) coverage
    try:
        cov.stop()
        cov.save()
        data = cov.get_data()

        covered_lines = set()
        coverage_score = 0.0

        if data:
            files = data.measured_files()
            if abs_path in files:
                analysis = cov._analyze(abs_path).numbers
                total = analysis.n_statements
                missed = analysis.n_missing
                if total > 0:
                    coverage_score = 100.0 * (total - missed) / total
                covered_lines = set(data.lines(abs_path))

        return coverage_score, is_pass, covered_lines

    except Exception as e:
        print("coverage 计算失败:", repr(e))
        return 0.0, is_pass, set()




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
    # os.kill = None
    os.system = None
    os.putenv = None
    os.removedirs = None
    os.rmdir = None
    os.fchdir = None
    os.setuid = None
    # os.fork = None  # 开启多线程
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


