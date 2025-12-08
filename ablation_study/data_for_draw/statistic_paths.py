import os
import logging

# 设置日志配置
def setup_logging(log_filename):
    logging.basicConfig(
        filename=log_filename,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def read_and_stat_from_file(file_path, step=5, logger=None):
    # 初始化统计变量
    total_sum = 0
    step_sum = 0
    step_count = 0
    coverage_stats = []

    # 读取文件内容
    with open(file_path, 'r') as file:
        for line in file:
            # 跳过空行或注释行
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # 分割每行内容
            parts = line.split(",")
            if len(parts) < 3:
                continue

            try:
                # 取最后一个数字
                path_value = int(parts[-1].strip())
            except ValueError:
                continue

            # 累加总和
            total_sum += path_value
            step_sum += path_value
            step_count += 1

            # 每达到步长，就记录一次
            if step_count == step:
                coverage_stats.append(step_sum)
                step_sum = 0  # Reset for the next step
                step_count = 0

    # 如果有剩余的数据没有填满一个步长，记录下来
    if step_count > 0:
        coverage_stats.append(step_sum)

    # 输出当前文件的统计结果（累加的形式）
    logger.info(f"File: {file_path}")
    logger.info(f"Total paths covered: {total_sum}")
    logger.info(f"Path coverage per step (cumulative):")
    cumulative_sum = 0
    for idx, stat in enumerate(coverage_stats, 1):
        cumulative_sum += stat
        logger.info(f"Step {idx}: {cumulative_sum}")
    logger.info("-" * 40)


def batch_process_folder(folder_path, step=5, log_filename='outputs_for_draw/llmseceval_coverage_stats.txt'):
    # 设置日志文件
    setup_logging(log_filename)

    # 检查文件夹是否存在
    if not os.path.exists(folder_path):
        logging.error(f"Folder {folder_path} does not exist.")
        return

    # 遍历文件夹中的所有文件
    for filename in os.listdir(folder_path):
        # 只处理文本文件
        if filename.endswith('.txt'):
            file_path = os.path.join(folder_path, filename)
            # 调用文件处理函数
            read_and_stat_from_file(file_path, step, logger=logging)


# 调用函数时传入文件夹路径和自定义步长
folder_path = 'results'  # 替换为你的文件夹路径
step = 83  # 你可以在这里设置步长 一般是数据集的数量
batch_process_folder(folder_path, step)
