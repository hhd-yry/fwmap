"""fwmap agent：LLM 取证 + 规则裁决。

分工（这是整个设计的核心）：
  - 静态分析（M1/M2/M3）产出**带证据的假设**：这条链的源、汇、via、guard 都能追到具体语句；
  - LLM 只做**取证**：读反编译代码，回答"值从哪进来、前面有没有上界检查"，必须引用语句编号；
  - 规则做**裁决**：把事实折成 CONFIRMED / REFUTED / REVIEW / UNPROVEN。

为什么不让 LLM 直接判"是不是漏洞"：手册 §7 记着那次失败（43 条回答里 35 条含糊其辞，
从不说"不知道"）。换成"抽事实"之后，模型只需要对**能被核对的东西**负责。
"""

from .cli import main, run, render_md  # noqa: F401

__all__ = ["main", "run", "render_md"]
