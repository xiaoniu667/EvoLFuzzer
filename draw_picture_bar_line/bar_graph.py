from typing import List, Union
from .graph import Graph
from .color import COLOR
import numpy as np


class BarGraph(Graph):
    def __init__(self, style_id: int = 1) -> None:
        super().__init__(style_id=style_id)

        self._bar_width = 0.3  # 柱状图宽度 [0-1] (default 0.8)
        self._group_threshold = 0.15  # 组间距
        self.show_values = False  # 是否显示数值
        self.value_fontsize = 8  # 数值字体大小
        self.value_color = "black"  # 数值颜色

    def plot(self, x_data: List[Union[str, int]], y_data: List[float]):
        """
        绘制一维柱状图

        ## Parameters
        x_data: x 轴数据
        y_data: y 轴数据
        """
        # x 轴坐标等距
        x_ticks = range(len(x_data))
        bars = self.ax.bar(x_ticks, y_data, width=self._bar_width, color=COLOR.get_colors(1, self.style_id))
        
        # 显示数值
        if self.show_values:
            self._add_value_labels(bars, y_data)
        
        # x 轴标签和位置的映射
        self.ax.set_xticks(x_ticks, x_data)

    def plot_2d(
        self, data: List[List[float]], group_names: List[str], column_names: List[str], emphasize_index: int = -1
    ):
        """
        绘制二维柱状图

        ## Parameters
        data: 二维列表,每个元素为一组数据
        group_names: 每个组的名称
        column_names: 每一列的名称
        emphasize_index: 高亮的列索引
        """
        assert np.shape(data) == (len(group_names), len(column_names)), "二维数据应为二维列表"

        group_len = len(group_names)
        column_len = len(column_names)

        if emphasize_index != -1:
            assert (
                type(emphasize_index) == int and emphasize_index < len(column_names) and emphasize_index >= 0
            ), f"emphasize_index应在[0, {len(column_names)})之间"

        # 如果列数很多, 考虑到组间距, 所以重新计算一下柱状图宽度
        if column_len >= 3:
            self._bar_width = (0.5 - self._group_threshold) / column_len * 2

        colors = COLOR.get_colors(column_len, self.style_id, emphasize_index)
        all_bars = []  # 存储所有柱状图对象


        for i in range(column_len):
            bar_pos = -column_len + 2 * i + 1
            x_ticks = [j + bar_pos / 2 * self._bar_width for j in range(group_len)]
            bar_data = [data[j][i] for j in range(group_len)]
            hatch_pattern = "\\\\\\" if i == emphasize_index else ""
            bars = self.ax.bar(
                x_ticks, bar_data, width=self._bar_width, color=colors[i], edgecolor="#E8E8E8", linewidth=0.3,
                hatch=hatch_pattern
            )
            # bars = self.ax.bar(
            #     x_ticks,
            #     bar_data,
            #     width=self._bar_width,
            #     color=colors[i],
            #     edgecolor="none",  #去掉所有柱子的边框
            #     linewidth=0  # 线宽设为0
            # )
            all_bars.append((bars, bar_data))  # 存储柱状图对象和对应的数据
            
            # 显示数值
            if self.show_values:
                self._add_value_labels(bars, bar_data)
        
        self.ax.set_xticks(range(group_len), group_names)
        self.ax.tick_params(bottom=False)

        self.legend = self.ax.legend(
            column_names,
            loc="upper center",  # 居中置顶
            ncols=column_len,  # 横向排布
            bbox_to_anchor=(0.5, 1.2),  # 置于图外侧
            handlelength=1,  # 图例长宽, 修改为正方形
            handleheight=1,  # 图例长宽, 修改为正方形
            handletextpad=0.4,  # 缩短文字和图例的间距
            fontsize=15,
            # fontsize="x-small" if column_len >= 7 else "medium",  # 图例文字大小
        )

    def plot_horizontal(self, y_data: List[Union[str, int]], x_data: List[float]):
        """
        绘制横向柱状图

        ## Parameters
        y_data: y 轴数据（标签）
        x_data: x 轴数据（数值）
        """
        # y 轴坐标等距
        y_ticks = range(len(y_data))
        self.ax.barh(y_ticks, x_data, height=self._bar_width, color=COLOR.get_colors(1, self.style_id))
        # y 轴标签和位置的映射
        self.ax.set_yticks(y_ticks, y_data)

    def add_line(self, y: int, line_style="-"):
        self.ax.axhline(y, linestyle=line_style, linewidth=0.5, color="black")
    
    def _add_value_labels(self, bars, values):
        """
        在柱状图上添加数值标签
        
        ## Parameters
        bars: matplotlib柱状图对象
        values: 对应的数值列表
        """
        for bar, value in zip(bars, values):
            height = bar.get_height()
            # 在柱状图顶部显示数值
            self.ax.text(
                bar.get_x() + bar.get_width() / 2.,  # x坐标：柱状图中心
                height + max(values) * 0.01,  # y坐标：柱状图顶部稍微向上一点
                f'{value:.2f}',  # 显示数值，保留2位小数
                ha='center',  # 水平居中
                va='bottom',  # 垂直底部对齐
                fontsize=self.value_fontsize,
                color=self.value_color
            )
