"""fwmap —— 固件攻击面地图。

入口：python -m fwmap scan <rootfs>
"""

from .scan import scan, ScanResult, Target
from .report import render_html

__version__ = "0.1.0"
__all__ = ["scan", "ScanResult", "Target", "render_html"]
