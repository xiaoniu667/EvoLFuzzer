import ast
import json
import logging
import signal
import time
from contextlib import contextmanager
from typing import List

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('path_coverage.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# 超时异常
class TimeoutException(Exception):
    pass


@contextmanager
def timeout(seconds: int):
    """超时上下文管理器"""

    def signal_handler(signum, frame):
        raise TimeoutException("Path computation timed out")

    try:
        # 设置信号处理（仅 Unix 系统支持）
        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(seconds)
        yield
    except ValueError:  # Windows 不支持 signal.SIGALRM
        start_time = time.time()
        yield
        if time.time() - start_time > seconds:
            raise TimeoutException("Path computation timed out")
    finally:
        signal.alarm(0)


class CFGNode:
    """控制流图节点"""

    def __init__(self, node_id: int, ast_node=None):
        self.id = node_id
        self.ast_node = ast_node
        self.successors: List['CFGNode'] = []
        self.is_exit = False

    def add_successor(self, node: 'CFGNode'):
        self.successors.append(node)


class CFGBuilder(ast.NodeVisitor):
    """构建简化的控制流图"""

    def __init__(self):
        self.nodes: List[CFGNode] = []
        self.current_id = 0
        self.entry_node = None
        self.exit_node = None
        self.last_nodes: List[CFGNode] = []

    def new_node(self, ast_node=None) -> CFGNode:
        node = CFGNode(self.current_id, ast_node)
        self.current_id += 1
        self.nodes.append(node)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """处理函数定义"""
        self.entry_node = self.new_node(node)
        self.exit_node = self.new_node()
        self.exit_node.is_exit = True
        self.last_nodes = [self.entry_node]

        for stmt in node.body:
            self.visit(stmt)

        for last in self.last_nodes:
            if last != self.exit_node:
                last.add_successor(self.exit_node)
        self.last_nodes = [self.exit_node]

    def visit_If(self, node: ast.If):
        """处理 if 语句"""
        condition_node = self.new_node(node)
        true_branch = self.new_node()
        false_branch = self.new_node() if node.orelse else self.exit_node

        for last in self.last_nodes:
            if last != self.exit_node:
                last.add_successor(condition_node)
        self.last_nodes = [condition_node]

        condition_node.add_successor(true_branch)
        prev_last = self.last_nodes
        self.last_nodes = [true_branch]
        for stmt in node.body:
            self.visit(stmt)

        if node.orelse:
            condition_node.add_successor(false_branch)
            self.last_nodes = [false_branch]
            for stmt in node.orelse:
                self.visit(stmt)

        self.last_nodes = [n for n in prev_last + [true_branch, false_branch] if n != self.exit_node]

    def visit_For(self, node: ast.For):
        """处理 for 循环，仅考虑进入和跳出"""
        loop_node = self.new_node(node)
        body_node = self.new_node()
        after_loop = self.new_node()

        for last in self.last_nodes:
            if last != self.exit_node:
                last.add_successor(loop_node)
        self.last_nodes = [loop_node]

        loop_node.add_successor(body_node)
        loop_node.add_successor(after_loop)

        prev_last = self.last_nodes
        self.last_nodes = [body_node]
        for stmt in node.body:
            self.visit(stmt)

        self.last_nodes = [after_loop]

    def visit_Return(self, node: ast.Return):
        """处理 return 语句"""
        return_node = self.new_node(node)
        for last in self.last_nodes:
            if last != self.exit_node:
                last.add_successor(return_node)
        return_node.add_successor(self.exit_node)
        self.last_nodes = [return_node]

    def visit_Expr(self, node: ast.Expr):
        """处理表达式语句"""
        expr_node = self.new_node(node)
        for last in self.last_nodes:
            if last != self.exit_node:
                last.add_successor(expr_node)
        self.last_nodes = [expr_node]


def get_all_paths(cfg: CFGBuilder) -> List[List[int]]:
    """通过迭代式 BFS 枚举所有路径"""
    paths = []
    queue = [(cfg.entry_node, [])]  # (节点, 当前路径)
    max_paths = 10000  # 最大路径限制
    max_nodes = 1000  # 最大节点限制

    if cfg.current_id > max_nodes:
        logger.warning("Too many CFG nodes, skipping path enumeration")
        return []

    while queue and len(paths) < max_paths:
        node, current_path = queue.pop(0)  # BFS 使用队列
        current_path = current_path + [node.id]

        if node.is_exit or not node.successors:
            paths.append(current_path)
            continue

        for succ in node.successors:
            queue.append((succ, current_path))

    unique_paths = {tuple(path) for path in paths}
    if len(paths) >= max_paths:
        logger.warning("Path limit reached, results may be incomplete")

    return [list(path) for path in unique_paths]


def compute_path_count(code: str, code_id: str, timeout_seconds: int = 5) -> int:
    """计算单个代码片段的路径总数，带超时"""
    try:
        with timeout(timeout_seconds):
            tree = ast.parse(code)
            cfg_builder = CFGBuilder()
            cfg_builder.visit(tree)

            if cfg_builder.current_id > 1000:
                logger.warning(f"Code {code_id} - Too many CFG nodes ({cfg_builder.current_id}), skipping")
                return 0

            paths = get_all_paths(cfg_builder)
            unique_paths = {tuple(path) for path in paths}

            logger.info(f"Code {code_id} - Total paths: {len(unique_paths)}")
            for i, path in enumerate(unique_paths, 1):
                logger.info(f"Code {code_id} - Path {i}: {path}")

            return len(unique_paths)

    except TimeoutException:
        logger.error(f"Code {code_id} - Path computation timed out after {timeout_seconds} seconds")
        return 0
    except SyntaxError as e:
        logger.error(f"Code {code_id} - Invalid Python code: {e}")
        return 0
    except Exception as e:
        logger.error(f"Code {code_id} - Error computing paths: {e}")
        return 0


def process_jsonl_file(jsonl_file: str, output_file: str = "path_coverage_results.txt",
                       timeout_seconds: int = 5) -> int:
    """处理 JSONL 文件，计算所有代码的路径总数并累加"""
    total_paths = 0

    try:
        with open(jsonl_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    code_id = data.get('ID', 'Unknown_ID')
                    code = data.get('Insecure_code', '')
                    if not code:
                        logger.warning(f"Code {code_id} - Empty code, skipping")
                        continue

                    path_count = compute_path_count(code, code_id, timeout_seconds)
                    total_paths += path_count

                    with open(output_file, 'a', encoding='utf-8') as out_f:
                        out_f.write(f"Code {code_id}: {path_count} paths\n")

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in line: {line.strip()} - Error: {e}")
                    continue

        logger.info(f"Total paths across all codes: {total_paths}")
        with open(output_file, 'a', encoding='utf-8') as out_f:
            out_f.write(f"\nTotal paths across all codes: {total_paths}\n")

        return total_paths

    except FileNotFoundError:
        logger.error(f"JSONL file {jsonl_file} not found")
        return 0
    except Exception as e:
        logger.error(f"Error processing JSONL file: {e}")
        return 0


def main(jsonl_file: str):
    """主函数，处理 JSONL 文件并计算路径总数"""
    logger.info("Starting path coverage analysis for JSONL file")
    total_paths = process_jsonl_file(jsonl_file)
    logger.info(f"Final total path count: {total_paths}")
    return total_paths


if __name__ == '__main__':
    jsonl_file = "vulnerability_data.jsonl"
    main(jsonl_file)