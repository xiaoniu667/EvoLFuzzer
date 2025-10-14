
# 定义数据维度
import numpy as np

from draw_picture_bar import BarGraph

a = 4
b = 4

# 数据矩阵
y = [
    [40.79, 23.69, 47.18, 14.69],   # RMA
    [54.79, 24.19, 62.02, 16.38],  # EvoPFuzzer_w/o_LLM
    [58.11, 25.47, 66.17, 16.95],   # EvoPFuzzer_w/o_EA
    [72.48, 29.43, 71.81, 20.90],  # EvoPFuzzer
]

# 转置数据以匹配 (a, b) = (3, 7)
y = np.array(y).T.tolist()  # 转置为 (3, 7)

# 自定义横纵坐标名称
group_names = ["HumanEval", "LLMSecEval", "MBPP","CWEval"]
column_names = ["RMA", "EvoPFuzzer_w/o_LLM", "EvoPFuzzer_w/o_EA", "EvoPFuzzer"]

# 检查名称列表长度是否匹配数据维度
if len(group_names) != a:
    raise ValueError(f"Expected {a} group names, but got {len(group_names)}")
if len(column_names) != b:
    raise ValueError(f"Expected {b} column names, but got {len(column_names)}")

# 初始化一个对象
graph = BarGraph()

# 启用数值显示
graph.show_values = True
graph.value_fontsize = 4  # 设置数值字体大小

# 传入数据/组/列的文字信息
graph.plot_2d(y, group_names, column_names)

# 调整x/y轴文字
graph.x_label = "Different DataSets"
graph.y_label = "Coverage Rate (%)"

# 保存图片
graph.save()