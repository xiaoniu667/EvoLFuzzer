import numpy as np
import matplotlib
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42
matplotlib.rcParams['font.size'] = 16  # 全局字体

from draw_picture_bar import BarGraph

a = 4
b = 4

# 数据
y = [
    [40.79, 23.69, 47.18, 14.69],   # RMA
    [54.79, 24.19, 62.02, 16.38],  # EvoPFuzzer_w/o_LLM
    [58.11, 25.47, 66.17, 16.95],   # EvoPFuzzer_w/o_EA
    [72.48, 28.43, 71.81, 20.90],   # EvoPFuzzer
]

y = np.array(y).T.tolist()

group_names = ["HumanEval", "LLMSecEval", "MBPP", "CWEval"]
column_names = ["RMA", "EvoLFuzzer_w/o_LLM", "EvoLFuzzer_w/o_EA", "EvoLFuzzer"]

# 初始化对象
graph = BarGraph()

# 显示数值，放大字体
graph.show_values = True
graph.value_fontsize = 7

# 画图
graph.plot_2d(y, group_names, column_names)

# 坐标轴标签
graph.x_label = "Different DataSets"
graph.y_label = "Coverage Rate (%)"

# 以 PDF 矢量格式保存
graph.save()
