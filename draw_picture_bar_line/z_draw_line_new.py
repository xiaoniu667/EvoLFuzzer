import matplotlib.pyplot as plt
import numpy as np
import os
from matplotlib import font_manager as fm

# 1. 加载本地字体
font_path = f"{os.path.dirname(__file__)}/consola-1.ttf"
if os.path.exists(font_path):
    fm.fontManager.addfont(font_path)
    plt.rcParams['font.family'] = 'Consolas'
else:
    print("本地字体不存在，使用默认字体")

plt.rcParams['font.size'] = 16
plt.rcParams['pdf.fonttype'] = 42
plt.rcParams['ps.fonttype'] = 42

# 2. x 轴
x_data = np.array([0, 1, 2, 3, 4, 5])

# 3. y 轴数据
# humaneval
# y_data = np.array([
#     [0, 389, 483, 533, 571, 590],
#     [0, 335, 385, 425, 449, 449],
#     [0, 285, 344, 383, 398, 398],
#     [0, 298, 313, 324, 331, 339],
#     [0, 298, 321, 330, 338, 348],
#     [0, 314, 343, 364, 377, 392],
#     [0, 276, 312, 332, 345, 356],
#     [0, 279, 298, 310, 322, 329],
# ])

# llmseceval
y_data = np.array([
    [0, 107, 122, 131, 134, 141],  # EvoLFuzzer
    [0, 112, 119, 121, 123, 125],  # EvoLFuzzer_w/o_LLM
    [0, 89, 100, 105, 112, 113],  # EvoLFuzzer_w/o_EA
    [0, 101, 105, 109, 114, 115],  # ACO
    [0, 103, 107, 111, 111, 112],  # PSO
    [0, 102, 105, 110, 111, 114],  # EA
    [0, 96, 98, 102, 102, 107],  # GA
    [0, 100, 106, 109, 112, 113],  # RMA
])

# cweval

# y_data = np.array([
#     [0, 29, 33, 38, 39, 39],   # EvoLFuzzer
#     [0, 26, 27, 30, 30, 32],   # EvoLFuzzer_w/o_LLM
#     [0, 23, 24, 25, 28, 29],   # EvoLFuzzer_w/o_EA
#     [0, 27, 27, 28, 28, 28],   # ACO
#     [0, 27, 27, 27, 27, 28],   # PSO
#     [0, 28, 28, 29, 30, 30],   # EA
#     [0, 28, 29, 29, 30, 30],   # GA
#     [0, 26, 27, 27, 27, 27],   # RMA
# ])

# #mbpp
# y_data = np.array([
#     [0, 169, 201, 219, 236, 239],   # EvoLFuzzer
#     [0, 181, 206, 213, 218, 222],   # EvoLFuzzer_w/o_LLM
#     [0, 135, 166, 176, 186, 190],   # EvoLFuzzer_w/o_EA
#     [0, 146, 154, 158, 162, 166],   # ACO
#     [0, 147, 155, 160, 163, 165],   # PSO
#     [0, 173, 183, 187, 189, 191],   # EA
#     [0, 159, 167, 173, 175, 183],   # GA
#     [0, 141, 147, 151, 153, 156],   # RMA
# ])

# securityeval
# y_data = np.array([
#     [0, 114, 126, 138, 154, 157],   # EvoLFuzzer
#     [0, 125, 135, 138, 139, 140],   # EvoLFuzzer_w/o_LLM
#     [0, 112, 123, 137, 139, 139],   # EvoLFuzzer_w/o_EA
#     [0, 120, 128, 131, 132, 132],   # ACO
#     [0, 120, 126, 127, 130, 131],   # PSO
#     [0, 122, 128, 129, 132, 132],   # EA
#     [0, 117, 123, 124, 126, 126],   # GA
#     [0, 122, 126, 128, 128, 128],   # RMA
#     ])




line_names = ['EvoLFuzzer', 'EvoLFuzzer_w/o_LLM', 'EvoLFuzzer_w/o_EA', 'ACO', 'PSO', 'EA', 'GA', 'RMA']

# 4. 颜色和标记
colors = ['#2D68C4', '#ED7D31', '#70AD47', '#C00000', '#7030A0', '#A16A2D', '#C76DB6', '#828182']
markers = ['s', 'P', '^', 'v', '*', 'x', 'D', 'h']

plt.figure(figsize=(7, 6))

for y, name, color, marker in zip(y_data, line_names, colors, markers):
    plt.plot(x_data, y, label=name, color=color, marker=marker, linewidth=2, markersize=7)

plt.xlabel("Epoch")
plt.ylabel("Path Coverage")
plt.xticks(x_data)
plt.yticks(fontsize=14)
plt.ylim(70, None)
plt.grid(True, linestyle='--', alpha=0.8)

plt.legend(loc='lower right', fontsize=10, markerscale=0.8, ncol=1, frameon=True, facecolor='white')

plt.tight_layout()
plt.savefig("ablation_llmseceval.pdf")  # 保存为 PDF
# plt.show()
