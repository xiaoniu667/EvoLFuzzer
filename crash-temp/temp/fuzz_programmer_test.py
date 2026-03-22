# -*- coding: utf-8 -*-
import faulthandler
import hashlib
import importlib
import importlib.util
import json
import os
import platform
import signal
import sqlite3
import tempfile
import traceback
import uuid
from contextlib import contextmanager
from io import BytesIO
from typing import Optional

import coverage


# ---------------------------------------------------------------------------
# 崩溃持久化工具（被 do_execute_test_case / do_execute_test_case_web 调用）
# ---------------------------------------------------------------------------

def save_crash_locally(crash_info: dict, test_input: dict):
    """
    将发现的崩溃以 JSON 形式写入 detected_crashes/ 目录。
    文件名格式：{错误类型}_{crash_id前8位}.json
    多进程安全：仅在文件不存在时写入，避免重复写入。
    """
    os.makedirs("humaneval/detected_crashes", exist_ok=True)
    filename = f"humaneval/detected_crashes/{crash_info['type']}_{crash_info['id'][:8]}.json"
    if not os.path.exists(filename):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({"info": crash_info, "input": test_input}, f, indent=4)


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

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
    return func, func_name, temp_file_path


class TimeoutException(Exception):
    """自定义超时异常"""
    pass


@contextmanager
def timeout(seconds):
    """上下文管理器，用于设置超时"""
    def signal_handler(signum, frame):
        raise TimeoutException("Test case execution exceeded time")

    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


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


# ---------------------------------------------------------------------------
# 核心执行逻辑
# ---------------------------------------------------------------------------

def do_execute_test_case(code, input_dict):
    """
    执行单个测试用例，返回 (coverage_score, is_pass, covered_lines)。
    同时捕获逻辑错误（排除 TimeoutException），计算堆栈 MD5 哈希，
    并将唯一崩溃写入 detected_crashes/ 目录。
    """
    fuc, func_name, temp_file_path = check_loader_code(code)
    cov_data_file = os.path.join(
        os.path.dirname(temp_file_path),
        f".coverage_{uuid.uuid4().hex}"
    )
    cov = coverage.Coverage(data_file=cov_data_file, include=[temp_file_path], omit=[])

    coverage_score = 0
    is_pass = False
    covered_lines = set()

    try:
        cov.start()
        with timeout(3):
            fuc(**input_dict)
        is_pass = True
    except Exception as e:
        is_pass = False
        tb_str = traceback.format_exc()
        # 只记录代码逻辑错误，跳过测试框架自身的超时异常
        if "TimeoutException" not in tb_str:
            crash_id = hashlib.md5(tb_str.encode()).hexdigest()
            crash_info = {
                "type": type(e).__name__,
                "msg": str(e),
                "stack": tb_str,
                "id": crash_id
            }
            save_crash_locally(crash_info, input_dict)
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
                covered_lines = set(data.lines(temp_file_path)) if data.lines(temp_file_path) else set()
        except Exception as e:
            print(f"Failed to compute coverage: {e}")

    return coverage_score, is_pass, covered_lines


def do_execute_test_case_web(code, input_dict):
    """
    Flask Web 应用的测试执行函数，返回 (coverage_score, is_pass, covered_lines)。
    同时捕获逻辑错误并写入 detected_crashes/。
    """
    _, _, temp_file_path = check_loader_code(code)
    abs_path = os.path.abspath(temp_file_path)

    cov_data_file = os.path.join(
        os.path.dirname(temp_file_path),
        f".coverage_{uuid.uuid4().hex}"
    )
    cov = coverage.Coverage(data_file=cov_data_file, include=[abs_path])
    cov.start()

    try:
        with timeout(3):
            spec = importlib.util.spec_from_file_location("temp_module", temp_file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

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

                module.render_template = fake_render_template
                app.jinja_env.get_or_select_template = lambda *a, **k: None
            except Exception as e:
                print("WARNING: Fake template patch failed:", e)

            client = app.test_client()

            if "session" in input_dict:
                with client.session_transaction() as sess:
                    for k, v in input_dict["session"].items():
                        sess[k] = v

            for k, v in input_dict.get("cookies", {}).items():
                client.set_cookie(server_name="localhost", key=k, value=v)

            headers = input_dict.get("headers", {}) or {}
            args = input_dict.get("args", {}) or {}
            form = input_dict.get("form", {}) or {}
            json_body = input_dict.get("json", None)
            raw_data = input_dict.get("data", None)
            values = input_dict.get("values", {}) or {}
            files = input_dict.get("files", {}) or {}

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

            if target_rule.arguments:
                for p in target_rule.arguments:
                    val = input_dict.get("path_params", {}).get(p, "1")
                    route_url = route_url.replace(f"<{p}>", str(val))
                    route_url = route_url.replace(f"<int:{p}>", str(val))
                    route_url = route_url.replace(f"<string:{p}>", str(val))

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

            if method == "POST":
                resp = client.post(route_url, **send_kwargs)
            elif method == "PUT":
                resp = client.put(route_url, **send_kwargs)
            elif method == "DELETE":
                resp = client.delete(route_url, **send_kwargs)
            else:
                resp = client.get(route_url, **send_kwargs)

            is_pass = (resp is not None and resp.status_code < 500)

    except Exception as e:
        tb_str = traceback.format_exc()
        if "TimeoutException" not in tb_str:
            crash_id = hashlib.md5(tb_str.encode()).hexdigest()
            crash_info = {
                "type": type(e).__name__,
                "msg": str(e),
                "stack": tb_str,
                "id": crash_id
            }
            save_crash_locally(crash_info, input_dict)
        try:
            cov.stop()
            cov.save()
        except:
            pass
        return 0.0, False, set()

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


# ---------------------------------------------------------------------------
# 可靠性防护
# ---------------------------------------------------------------------------

def reliability_guard(maximum_memory_bytes: Optional[int] = None):
    """禁用可能干扰测试的破坏性功能"""
    if maximum_memory_bytes is not None:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (maximum_memory_bytes, maximum_memory_bytes))
        resource.setrlimit(resource.RLIMIT_DATA, (maximum_memory_bytes, maximum_memory_bytes))
        if not platform.uname().system == 'Darwin':
            resource.setrlimit(resource.RLIMIT_STACK, (maximum_memory_bytes, maximum_memory_bytes))

    faulthandler.disable()

    import os as _os
    _os.environ['OMP_NUM_THREADS'] = '1'

    _os.system = None
    _os.putenv = None
    _os.removedirs = None
    _os.rmdir = None
    _os.fchdir = None
    _os.setuid = None
    _os.forkpty = None
    _os.killpg = None
    _os.rename = None
    _os.renames = None
    _os.truncate = None
    _os.replace = None
    _os.fchmod = None
    _os.fchown = None
    _os.chmod = None
    _os.chown = None
    _os.chroot = None
    _os.lchflags = None
    _os.lchmod = None
    _os.lchown = None

    import shutil
    shutil.rmtree = None
    shutil.move = None
    shutil.chown = None

    import subprocess
    subprocess.Popen = None

    import sys
    sys.modules['ipdb'] = None
    sys.modules['joblib'] = None
    sys.modules['psutil'] = None
    sys.modules['tkinter'] = None
