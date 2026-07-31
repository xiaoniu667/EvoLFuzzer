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


def plot_coverage_from_txt(folder_path, output_dir, title, result_name, step, legend_order=None):
    """
    绘制 Path Coverage 曲线，输出高分辨率 PNG 和 PDF，字体更大，线条更粗。
    """
    if legend_order is None:
        legend_order = ['EvoLFuzzer', 'RMA']  # 默认图例顺序
    # 【优化点1】统一并规范全局字体设置
    # 学术论文推荐使用无衬线字体(如 Arial, Helvetica) 或 罗马字体(Times New Roman)
    font_path = 'consola-1.ttf'
    if os.path.exists(font_path):
        try:
            fm.fontManager.addfont(font_path)
            plt.rcParams['font.family'] = 'Consolas'
        except Exception as e:
            print(f"无法加载字体 {font_path}: {e}")
            plt.rcParams['font.family'] = 'sans-serif'
            plt.rcParams['font.sans-serif'] = ['Arial', 'Helvetica', 'DejaVu Sans']
    else:
        print(f"字体文件 {font_path} 不存在，将使用学术默认字体 Arial")
        plt.rcParams['font.family'] = 'sans-serif'
        plt.rcParams['font.sans-serif'] = ['Arial', 'Helvetica', 'DejaVu Sans']

    # 检查输入文件夹
    if not os.path.exists(folder_path):
        print(f"文件夹 {folder_path} 不存在！")
        return

    os.makedirs(output_dir, exist_ok=True)

    data_list = []
    file_names = []

    # 读取所有 txt 文件
    for file in os.listdir(folder_path):
        if not file.endswith('.txt'):
            continue
        file_path = os.path.join(folder_path, file)
        try:
            data = pd.read_csv(file_path, header=None, names=['Index', 'Task', 'Branch_Coverage'])
            data['Cumulative_Coverage'] = data['Branch_Coverage'].cumsum()

            round_breaks = find_round_breaks(data, step)

            # 索引 → 轮次映射
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
    fig, ax = plt.subplots(figsize=(16, 12))  # 保持大尺寸
    colors = ['#ED7D31FF', '#5B9BD5FF']

    for i, (data, label) in enumerate(zip(sorted_data_list, sorted_file_names)):
        # 【优化点2】数据折线加粗至 5.5，让对比极其醒目
        ax.plot(data['Round'], data['Cumulative_Coverage'],
                label=label, color=colors[i % len(colors)], linestyle='-', linewidth=5.5)

    # 字体和标签设置
    if title:  # 如果 title 不为空才设置
        ax.set_title(title, fontsize=48, fontweight='bold', pad=30)

    ax.set_xlabel("Rounds", fontsize=58, fontweight='bold', labelpad=15)
    #
    # ax.set_ylabel("Cumulative Path Coverage", fontsize=44, fontweight='bold', labelpad=25)

    # 【优化点3】加粗并放大坐标轴刻度线 (Ticks) 和数字
    ax.tick_params(axis='both', which='major', labelsize=58, width=3, length=12, pad=10)

    # 设置刻度标签为粗体
    for label in ax.get_xticklabels():
        label.set_fontweight('bold')
    for label in ax.get_yticklabels():
        label.set_fontweight('bold')

    # 【优化点4】加粗坐标轴外边框 (Spines)，匹配大字体
    for spine in ax.spines.values():
        spine.set_linewidth(3)

    # 【优化点5】增强图例的可读性：添加纯白背景框和黑色边框，图例文字加粗
    # legend = ax.legend(fontsize=32, loc='upper left', bbox_to_anchor=(0.02, 0.98),
    #                    frameon=True, edgecolor='black', facecolor='white', framealpha=0.9)
    legend = ax.legend(fontsize=55, loc='lower right', bbox_to_anchor=(1.00, 0.00),
                       frameon=True)
    legend.get_frame().set_linewidth(2.5)  # 图例边框加粗
    for text in legend.get_texts():
        text.set_fontweight('bold')  # 图例文字加粗

    # 【优化点6】
    ax.grid(True, linestyle='--', linewidth=1.5, alpha=0.6)
    # 移除网格线
    # ax.grid(False)

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

    # 保存文件
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file_pdf = os.path.join(output_dir, f'coverage_{result_name}_{timestamp}.pdf')

    # 顺便生成一张高分辨率PNG，方便你在Word中预览或插入
    output_file_png = os.path.join(output_dir, f'coverage_{result_name}_{timestamp}.png')

    # 【优化点7】添加 dpi=600，保证极致清晰度
    plt.savefig(output_file_pdf, bbox_inches='tight', format='pdf', dpi=600)
    plt.savefig(output_file_png, bbox_inches='tight', format='png', dpi=600)
    plt.close()

    print(f"图表已保存为: \n {output_file_pdf} \n {output_file_png}")


if __name__ == '__main__':
    import json

    with open('plot_configs.json', 'r', encoding='utf-8') as f:
        configs = json.load(f)

    for i, config in enumerate(configs, 1):
        print(f"\n[{i}/{len(configs)}] 正在处理: {config['result_name']}")
        plot_coverage_from_txt(
            folder_path=config['folder_path'],
            output_dir=config['output_dir'],
            title=config.get('title', ''),
            result_name=config['result_name'],
            step=config['step']
        )

    print(f"\n完成！共处理 {len(configs)} 个配置")