# blue-team-agent — Copilot 项目指令

> 本文件是仓库级强制约定。任何生成的代码若与本章冲突，以本章为准。

## 1. 硬件上限（硬性，不可假设更高）

| 资源 | 上限 |
| --- | --- |
| GPU | NVIDIA RTX 5060（Blackwell, sm_120），**8GB VRAM** |
| RAM | 32GB DDR5 |
| CPU | Intel Core i7 14代+，20 线程 |
| 存储 | 50GB+ NVMe SSD |
| CUDA / PyTorch | CUDA 12.4+ / PyTorch 2.0+ |

- **显存红线 7.5GB**：任何脚本一旦检测到 `torch.cuda.max_memory_reserved() > 7.5GB`
  必须打印告警，并给出「降低 batch_size / 缩短 max_seq_length / 提高 gradient_accumulation_steps」的具体建议。
- 单卡训练，不引入任何多卡/分布式依赖。

## 2. 技术栈（不得替换）

| 环节 | 选型 |
| --- | --- |
| 微调框架 | **Unsloth（首选）**，备选 LLaMA-Factory |
| 量化 | QLoRA **4-bit NF4 + double quantization** |
| 基座模型 | `Qwen/Qwen2.5-3B-Instruct` |
| 推理部署 | Ollama + GGUF **Q4_K_M** |
| 对抗环境 | CybORG++（基于 CAGE Challenge 2/4） |
| **禁用** | `flash-attn`（5060 兼容性未验证）、`deepspeed`（单卡无必要） |

- 注意力实现显式指定 `attn_implementation="sdpa"`，禁止任何 `flash_attention_2`。
- 优先依赖：`bitsandbytes`, `peft`, `transformers`, `trl`, `accelerate`, `unsloth`。

## 3. 代码生成规范

- 训练脚本必须包含：`gradient_checkpointing=True`（Unsloth 用 `"unsloth"`）+ **bf16/fp16 混合精度**。
- 每步训练必须打印：`loss`、`learning_rate`、`GPU 显存占用`。
- 所有配置文件为 **YAML**；所有路径为 **相对路径**（统一相对项目根，脚本内用 `Path(__file__).resolve().parents[n]` 解析）。
- 网络请求必须设置**超时 + 重试上限**。
- 不可逆操作（删除、写入、网络配置变更）必须实现**两阶段确认**。
- 日志一律走 `security/sanitize.py`，禁止输出完整 IP / Token / 密码。
- 模型输出必须先通过 `security/action_schema.py` 的 schema 校验才能执行动作。
- 禁止硬编码任何密钥、口令、Token。

## 4. 目录约定

```
blue-team-agent/
├── .github/copilot-instructions.md   # 本文件
├── security/                         # 安全编码规则与工具（脱敏 / schema / 确认门）
├── training/                         # QLoRA 微调
├── cyber_range/                      # CybORG++ 靶场与红蓝自博弈闭环
├── deployment/                       # Ollama / GGUF 部署
├── data/                             # SFT / Eval / 轨迹数据
└── logs/                             # 运行日志与报告（默认 gitignore）
```

## 5. 安全边界（本项目为防御方工具）

- 本仓库面向**蓝队应急响应**：检测、取证、遏制、恢复。
- 不得生成针对真实第三方系统的攻击、免杀、持久化、横向移动利用代码。
- 靶场（`cyber_range/`）中的红队行为仅允许在**本地隔离仿真环境**内运行。
