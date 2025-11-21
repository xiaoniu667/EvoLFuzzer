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
    """
    total_len = len(df)
    breaks = list(range(0, total_len + step, step))
    if breaks[-1] > total_len:
        breaks[-1] = total_len
    elif breaks[-1] < total_len:
        breaks.append(total_len)
    return breaks

def plot_coverage_from_txt(folder_path, output_dir, title, result_name, step):
    """
    绘制 Path Coverage 曲线，输出高分辨率 PNG 和 PDF，字体更大，标题和纵坐标距离更远。
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
    legend_order = ['EvoLFuzzer', 'EvoLFuzzer_wo_EA', 'EvoLFuzzer_wo_LLM']  # 调整图例顺序

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
                round_start = i
                round_end = i + 1
                data.loc[(data['Index'] >= start_idx) & (data['Index'] < end_idx), 'Round'] = \
                    round_start + (data['Index'] - start_idx) / (end_idx - start_idx) * (round_end - round_start)

            data_list.append(data)
            file_names.append(file.replace('.txt', ''))

        except Exception as e:
            print(f"读取文件 {file_path} 时出错: {e}")
            continue

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
    fig, ax = plt.subplots(figsize=(16, 12))  # 大尺寸
    colors = ['#ED7D31FF', '#5B9BD5FF', '#70AD47FF']  # 橙, 蓝, 绿
    linestyles = ['-', (5, 5), (3, 5, 1, 5)]  # 实线, 虚线, 点划线

    for i, (data, label) in enumerate(zip(sorted_data_list, sorted_file_names)):
        plot_kwargs = {
            'color': colors[i % len(colors)],
            'linestyle': '-',  # 默认使用实线
            'linewidth': 4,    # 粗线条，更清晰
        }
        if isinstance(linestyles[i % len(linestyles)], tuple):
            plot_kwargs['dashes'] = linestyles[i % len(linestyles)]
        display_label = label.replace('_wo_', '_w/o_')
        ax.plot(data['Round'], data['Cumulative_Coverage'], label=display_label, **plot_kwargs)

    # 增大字体并增加标题和ylabel的距离
    ax.set_title(title, fontsize=48, fontweight='bold', pad=30)       # pad增加标题与图像的距离
    ax.set_xlabel('Epoch', fontsize=40, fontweight='bold', labelpad=20)   # labelpad增加x轴与图像的距离
    ax.set_ylabel('Path Coverage', fontsize=40, fontweight='bold', labelpad=25)  # labelpad增加y轴与图像的距离
    ax.tick_params(axis='both', labelsize=32)
    ax.legend(fontsize=24, loc='upper left', bbox_to_anchor=(0.02, 0.98), borderaxespad=0., handlelength=3)
    ax.grid(True, linestyle='--', linewidth=1, alpha=0.6)

    try:
        max_round = max(d['Round'].max() for d in sorted_data_list)
        min_cov = min(d['Cumulative_Coverage'].min() for d in sorted_data_list)
        max_cov = max(d['Cumulative_Coverage'].max() for d in sorted_data_list)
        ax.set_xlim(0, max_round)
        ax.set_ylim(max(min_cov - 10, 0), max_cov + 10)
        ax.set_xticks(list(range(0, int(max_round) + 2)))
    except Exception as e:
        print(f"设置坐标轴时出错: {e}")

    plt.tight_layout()

    # 保存文件，高分辨率PNG + PDF矢量图
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file_pdf = os.path.join(output_dir, f'coverage_{result_name}_Ablation_{timestamp}.pdf')

    plt.savefig(output_file_pdf, bbox_inches='tight', format='pdf')
    plt.close()

    print(f"图表已保存为: {output_file_pdf}")


if __name__ == '__main__':
    folder_path = './inputs/human_10seed_5epoch_ablation'
    output_dir = 'results/temp'
    title = "HumanEval Dataset"
    result_name = "HumanEval"
    step = 164
    plot_coverage_from_txt(folder_path, output_dir, title, result_name, step)
