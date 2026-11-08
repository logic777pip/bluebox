# 交付包说明（PACKAGING.md）

本仓库由 `build_release.py` 生成三个互不重叠的产物。**源码包里不含任何权重、二进制、日志和缓存**。

| 产物 | 内容 | 体积 | 去向 |
| --- | --- | --- | --- |
| `blue-team-agent-code-v1.0.0.zip` | 纯源码 + 文档 + 示例数据 | < 15 MB | GitHub 仓库 |
| `blue-team-agent-lora-v2-v1.0.0.zip` | `qwen2.5-3b-blue-team-lora-v2/` 全量（adapter + checkpoint + 全部配置/分词器） | 506 MB | 网盘 / HuggingFace |
| `blue-team-agent-win64-nomodel-v1.0.0.zip` | 源码 + llama.cpp 预编译二进制 + 启动脚本 | 590 MB | GitHub Release |
| `blue-team-agent-win64-full-v1.0.0.zip` | 上面两个 + `qwen2.5-3b-blue-team-q4_k_m.gguf` | 2.4 GB | 网盘（GitHub 单文件上限 2 GB） |

## 为什么 GGUF 不进源码仓库

`llama-server` 只加载 `.gguf`，而 LoRA adapter 是低秩增量、不能直接服务：

1. `tools/merge_adapter.py` 把 adapter 合并进 `Qwen/Qwen2.5-3B-Instruct` 全权重
2. `deployment/llamacpp/deploy_llamacpp.py convert` 转 GGUF 并量化到 Q4_K_M
3. `deploy_llamacpp.py serve` 加载 GGUF

发布包直接带第 2 步的产物，因此跳过合并/转换（`cmd_convert` 检测到 GGUF 已存在会直接返回 0）。

## 复现打包

打包脚本 `build_release.py` **不在仓库内**（它必然内嵌脱敏用的路径映射表，进仓库等于把被脱敏的内容写回去）。
它位于项目上一级的 `dist/` 目录，对源码目录**只读**：所有清洗都发生在 staging 副本上。

```bash
python ../dist/build_release.py     # 生成 staging + 四个 zip + SHA256SUMS.txt
```
