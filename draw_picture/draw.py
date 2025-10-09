import pandas as pd
import matplotlib
matplotlib.use('Agg')  # 非交互模式，适合服务器
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import os
import datetime


def find_round_breaks(df, step):
    """
    根据给定的步长 step 自动生成轮次边界。
    例如：step=164 -> [0, 164, 328, ... len(df)]
    """
    total_len = len(df)
    breaks = list(range(0, total_len + step, step))  # 按步长生成
    if breaks[-1] > total_len:
        breaks[-1] = total_len  # 确保最后一个不超过总长度
    elif breaks[-1] < total_len:
        breaks.append(total_len)  # 确保最后一轮包含结尾
    return breaks


def plot_coverage_from_txt(folder_path, output_dir, title, result_name,step):
    """
    从指定文件夹中读取 TXT 文件，绘制 Path Coverage 曲线图。
    自动检测每个文件的轮次边界，轮数从 0 开始。
    """

    # 设置字体
    font_path = 'consola-1.ttf'
    if os.path.exists(font_path):
        try:
            fm.fontManager.addfont(font_path)
            plt.rcParams['font.family'] = 'Consolas'
        except Exception as e:
            print(f"无法加载字体 {font_path}: {e}")
            plt.rcParams['font.family'] = 'sans-serif'
    else:
        print(f"字体文件 {font_path} 不存在，将使用默认字体")
        plt.rcParams['font.family'] = 'sans-serif'

    # 检查输入文件夹
    if not os.path.exists(folder_path):
        print(f"文件夹 {folder_path} 不存在！")
        return

    os.makedirs(output_dir, exist_ok=True)

    data_list = []
    file_names = []
    legend_order = ['EvoPFuzzer', 'RMA']  # 可根据需要调整

    # 读取所有 txt 文件
    for file in os.listdir(folder_path):
        if not file.endswith('.txt'):
            continue
        file_path = os.path.join(folder_path, file)
        try:
            data = pd.read_csv(file_path, header=None, names=['Index', 'Task', 'Branch_Coverage'])
            data['Cumulative_Coverage'] = data['Branch_Coverage'].cumsum()

            round_breaks = find_round_breaks(data, step)
            print(f"{file} 自动检测到轮次边界: {round_breaks}")

            # 索引 → 轮次映射（从 0 开始）
            data['Round'] = 0.0
            for i in range(len(round_breaks) - 1):
                start_idx = round_breaks[i]
                end_idx = round_breaks[i + 1]
                round_start = i        # 改成从 0 开始
                round_end = i + 1
                data.loc[(data['Index'] >= start_idx) & (data['Index'] < end_idx), 'Round'] = \
                    round_start + (data['Index'] - start_idx) / (end_idx - start_idx) * (round_end - round_start)

            data_list.append(data)
            file_names.append(file.replace('.txt', ''))

        except Exception as e:
            print(f"读取文件 {file_path} 时出错: {e}")
            continue

    # 没有数据就退出
    if not data_list:
        print("没有成功加载任何数据文件！")
        return

    # 按 legend_order 排序
    sorted_data_list, sorted_file_names = [], []
    for label in legend_order:
        if label in file_names:
            idx = file_names.index(label)
            sorted_data_list.append(data_list[idx])
            sorted_file_names.append(file_names[idx])
    for label, data in zip(file_names, data_list):
        if label not in legend_order:
            sorted_data_list.append(data)
            sorted_file_names.append(label)

    # 绘图
    fig, ax = plt.subplots(figsize=(12, 8))
    colors = ['#ED7D31FF', '#5B9BD5FF']

    for i, (data, label) in enumerate(zip(sorted_data_list, sorted_file_names)):
        ax.plot(data['Round'], data['Cumulative_Coverage'],
                label=label, color=colors[i % len(colors)], linestyle='-', linewidth=2)

    ax.set_title(title, fontsize=16)
    ax.set_xlabel('Epoch', fontsize=12)
    ax.set_ylabel('Path Coverage', fontsize=12)
    ax.legend()
    ax.grid(True, linestyle='--', linewidth=1, alpha=0.8)

    try:
        max_round = max(d['Round'].max() for d in sorted_data_list)
        min_cov = min(d['Cumulative_Coverage'].min() for d in sorted_data_list)
        max_cov = max(d['Cumulative_Coverage'].max() for d in sorted_data_list)
        ax.set_xlim(0, max_round)
        ax.set_ylim(max(min_cov - 10, 0), max_cov + 10)
        ax.set_xticks(list(range(0, int(max_round) + 2)))  # +2 是为了多显示一个
    except Exception as e:
        print(f"设置坐标轴时出错: {e}")

    plt.tight_layout()

    output_file = os.path.join(
        output_dir,
        f'coverage_{result_name}_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
    )
    plt.savefig(output_file, dpi=300, bbox_inches='tight', format='png')
    plt.close()
    print(f"图表已保存为: {output_file}")


if __name__ == '__main__':
    # 文件夹路径
    folder_path = './inputs/security_10seed_5epoch'
    output_dir = 'results'
    # 标题
    title = "SecurityEval Dataset"
    # 结果文件名部分
    result_name = "SecurityEval"
    # 轮次步长（数据集的数量）
    step = 121
    plot_coverage_from_txt(folder_path, output_dir, title, result_name,step)
