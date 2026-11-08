# -*- coding: utf-8 -*-
"""gui/ — 本地控制台（纯标准库）。

分层与依赖方向
--------------

    gui/static/*        前端（HTML/CSS/JS，零外部资源，离线可用）
        ↓ fetch
    gui/server.py       HTTP 层：绑定 127.0.0.1、令牌校验、路由、只读模式
        ↓
    gui/core.py         服务层：全部能力都在这里，复用既有模块
        ↓
    sandbox/ security/ actions/ forensics/ tools/    既有能力，**不复制实现**

三条纪律
--------

1. **GUI 是薄壳。** 不重写任何安全逻辑，只调用既有函数，因此硬拒绝、
   `execute_enabled` 闸门、策略检查、读回验证全部照旧生效。
2. **默认只读。** 未显式放开时进入只读模式，页面能看不能改。
3. **每个改动都留痕。** 落到 `logs/gui_undo.jsonl`。

为什么是 Web UI 而不是 tkinter
-----------------------------

本机 tkinter 可用，但选了本地 Web 界面：
* 零新依赖仍是纯标准库（`http.server`），不违背项目的依赖纪律；
* "白色简洁"用 CSS 完全可控，tkinter 的观感与主题很难做到；
* 最重要的：**可以被自动化验证**——我可以真的把页面打开、渲染、点按钮，
  确认界面上显示的是真实数据而不是一层好看的壳。tkinter 做不到这点。
"""
from __future__ import annotations

__all__ = ["core", "server", "tray"]
