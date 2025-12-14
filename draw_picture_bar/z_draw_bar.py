import matplotlib
import numpy as np

matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42
matplotlib.rcParams['font.size'] = 16  # 全局字体

from draw_picture_bar_line import BarGraph


a = 5
b = 8
# ================================
# y 按列（竖着）设置：每个子列表对应一个方法（长度为 5，按数据集顺序）
# 数据集顺序（行顺序）：["HumanEval", "LLMSecEval", "MBPP", "SecurityEval", "CWEval"]
# 方法顺序（列顺序）：
# ["RMA", "GA", "EA", "PSO", "ACO", "EvoPFuzzer"]
# ================================
y = [
    # RMA
    [40.17, 26.04, 46.29, 16.43, 31.40],
    # GA
    [43.73, 24.65, 54.30, 16.17, 34.88],
    # EA
    [48.16, 26.27, 56.68, 16.94, 34.88],
    # PSO
    [42.75, 25.81, 48.96, 16.82, 32.56],
    # ACO
    [41.65, 26.50, 49.26, 16.94, 32.56],
    # EvoLFuzzer_w/o_EA
    [48.91, 26.04, 56.38, 17.84, 33.72],
    # EvoLFuzzer_w/o_LLM
    [55.14, 28.80, 65.89, 17.97, 37.21],
    # EvoLFuzzer
    [72.48, 32.49, 70.92, 20.15, 45.35],
]

y = np.array(y).T.tolist()

# ================================
# 名称设置
# ================================
group_names = ["HumanEval", "LLMSecEval", "MBPP", "SecurityEval", "CWEval"]

column_names = [
    "RMA",
    "GA",
    "EA",
    "PSO",
    "ACO",
    "EvoLFuzzer_w/o_EA",
    "EvoLFuzzer_w/o_LLM",
    "EvoLFuzzer"
]

# 初始化对象
graph = BarGraph()

graph.show_values = True
graph.value_fontsize = 5

graph.style_id = 11
emphasize_index = 7

graph.width_picture = True

# 绘图
graph.plot_2d(y, group_names, column_names,emphasize_index)

# 坐标轴标签
graph.x_label = ""
graph.y_label = "Path Coverage (%)"

# 保存 PDF 矢量图
graph.save()
