import matplotlib
import numpy as np

from draw_picture_bar_line import LineGraph

matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42
matplotlib.rcParams['font.size'] = 16  # 全局字体

# 随机生成一个 5 x 7 的数据
a = 4
b = 6

y_data = np.array([
    [0, 107, 122, 131, 134, 141],
    [0, 112, 119, 121, 123, 125],
    [0, 89, 100, 105, 112, 113],
    [0, 100, 106, 109, 112, 113],
])

# y_data = np.array([
#     [0, 389, 483, 533, 571, 590],
#     [0, 335, 385, 425, 449, 449],
#     [0, 285, 344, 383, 398, 398],
#     [0, 279, 298, 310, 322, 329],
# ])


# y_data = np.array([
#     [0, 29, 33, 38, 39, 39],
#     [0, 26, 27, 30, 30, 32],
#     [0, 23, 24, 25, 28, 29],
#     [0, 26, 27, 27, 27, 27],
# ])

# y_data = np.array([
#     [0, 181, 206, 213, 218, 222],
#     [0, 169, 201, 219, 236, 239],
#     [0, 135, 166, 176, 186, 190],
#     [0, 141, 147, 151, 153, 156],
# ])

# y_data = np.array([
#     [0, 114, 126, 138, 154, 157],
#     [0, 125, 135, 138, 139, 140],
#     [0, 112, 123, 137, 139, 139],
#     [0, 122, 126, 128, 128, 128],
# ])

x_data = [i for i in range(0, b)]

line_names = ['EvoLFuzzer', 'EvoLFuzzer_w/o_LLM', 'EvoLFuzzer_w/o_EA', 'RMA']  # 改成你论文里真实的名称

# 初始化一个对象
graph = LineGraph()
graph.style_id = 12

# 传入数据/组/列的文字信息
graph.plot_2d(x_data, y_data, line_names)

# 调整x/y轴文字
graph.x_label = "Epoch"
graph.y_label = "Path Coverage"

# 保存图片
graph.save()
