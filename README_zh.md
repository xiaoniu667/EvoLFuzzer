# **EvoLFuzzer - 基于进化算法的大语言模型代码模糊测试框架**
## 📘 概述
**EvoLFuzzer** 是一个结合 **进化算法（Evolutionary Algorithms）** 与 **大语言模型语义引导** 的白盒模糊测试（White-box Fuzzing）框架，旨在系统化评估并增强大语言模型（LLM）生成代码的安全性。  
该框架通过 **代码语义理解 + 覆盖率反馈 + 种子进化策略**，能够在多个开源基准数据集上显著提升测试路径覆盖率与漏洞触达能力。

项目提供：

+ EvoLFuzzer 的完整系统实现
+ 可复现实验环境与配置
+ 多种基准方法与对照实验
+ 含路径覆盖率、漏洞检测等指标的评估模块
+ 集成了消融实验
+ 参数敏感性实验

---

## 🔥 主要特性
+ 🚀 **进化式模糊测试**：通过多轮进化策略动态生成与优化测试用例
+ 🤖 **大语言模型引导**：集成 DeepSeek-V3.2-Exp（deepseek-chat）进行代码生成与语义变异
+ 📊 **覆盖率驱动反馈**：使用 Coverage 工具采集路径覆盖率
+ 🔒 **面向安全漏洞检测**：专注于识别 LLM 生成代码中的潜在安全缺陷
+ 📈 **多轮进化收敛分析**：支持可视化覆盖率趋势与迭代行为

---

## 🖥 实验环境
### **硬件环境**
+ **CPU**：Intel Core i9-10900X（10 核 / 20 线程）
+ **内存**：128 GB RAM
+ **系统**：Ubuntu 22.04 LTS（64-bit）

### **软件依赖**
+ **LLM 模型**：DeepSeek-V3.2-Exp
+ **覆盖率工具**：Coverage
+ **Python**：3.10

### **实验设置**
+ 初始种子数量：**10**
+ 种子轮数：**5**
+ 重复实验次数：**5（结果取平均）**

---

## 📚 支持的数据集
EvoLFuzzer 在以下五个广泛使用的自然语言代码生成数据集上进行评估：

1. **HumanEval** – 手工编写的编程问题集合
2. **LLMSecEval** – 专注于大模型安全生成行为评估
3. **MBPP** – Google 提供的小型 Python 编程任务集
4. **CWEval** – 基于通用弱点枚举（CWE）的安全漏洞数据集
5. **SecurityEval** – 面向软件安全场景的代码生成评估集

---

## 🚀 使用方法
### 1. **安装**
```plain
# 克隆仓库
git clone https://github.com/xiaoniu667/EvoLFuzzer.git
cd EvoLFuzzer

# 安装依赖
pip install -r requirements.txt
```

---

## 2. **快速运行**
### ▶ 配置 LLM API（必做）
修改 `llm_utils.py`，填入自己的 DeepSeek API Key：

```plain
openai.api_base = "https://api.deepseek.com/v1"
openai.api_key = ""  # 在此替换为你的 key
model = "deepseek-chat"
```

---

### ▶ 运行种子生成
```plain
python main.py --method evolfuzzer --dataset HumanEval --epochs 5
```

---

### ▶ 运行模糊测试(路径覆盖测试)
```plain
python test_coverage.py
```

---

## 3. **参数说明**
+ `--method`  
  指定所使用的模糊测试方法。可选方法包括：  
  `evolfuzzer`、`ea`、`ga`、`pso`、`aco`、`rma`。  
  默认值为 **evolfuzzer**。
+ `--dataset`  
  指定要测试的基准数据集。当前项目支持的五个数据集包括：  
  `HumanEval`、`CWEval`、`MBPP`、`LLMSecEval`、`SecurityEval`。  
  默认使用 **HumanEval** 数据集。
+ `--epochs`  
  设置种子演化的轮数（即演化迭代次数）。  
  可设置为任意整数（如 1–10），默认值为 **5**。
---

## 🐳 使用 Docker 运行（推荐 ✔）
为避免模糊测试执行真实不安全代码，**强烈推荐在 Docker 环境中运行本项目**。

---

## 📂 项目结构
```plain
EvoLFuzzer/
├── ablation_study/                 # 消融实验
├── agent/                          # LLM 代理与种子生成模块
├── datasets/                       # 基准数据集
├── deepseek_coder/                 # DeepSeekCoder 生成的数据集
├── draw_picture/                   # 收敛分析可视化图
├── draw_picture_bar_line/          # 柱状图 / 折线图可视化
├── origin_dataset_prompts/         # 原始数据集及 DeepSeekCoder 输出
├── parameter_study/                # 参数敏感性实验
├── prompts/                        # 提示词模板
├── results/                        # 路径覆盖结果
├── seed_results/                   # 种子生成结果
├── single_thread/                  # 单线程版本
├── static_dataset/                 # 漏洞统计数据
│......
├── create_seed_xxxx                # 不同方法创建种子
├── fuzz_programmer_test_muti.py    # 多线程模糊测试程序（文件）
└── llm_utils.py                    # LLM 工具函数
```

---

## 📈 实验结果
框架可输出：

+ 安全数据集中触达漏洞统计
+ EvoLFuzzer vs. baseline 方法的路径覆盖率对比
+ 多轮进化的收敛曲线与趋势分析
+ 参数敏感性分析
+ 消融实验结果

## 🤝 贡献
欢迎提交 Issue 与 Pull Request！

提交前请确保：

1. 遵循项目代码风格
2. 添加必要测试
3. 更新相关文档

---

## 🙏 致谢
+ 感谢 DeepSeek 提供强大的代码生成模型支持
+ 感谢各基准数据集维护者
+ 感谢开源社区的贡献与支持

---

## 📬 联系方式
如有问题或建议，欢迎联系：

**📧** Email: zhuyiwen@st.xatu.edu.cn

