"""生成简版 Word 实验报告（含三张运行截图）。

图片来自会话附件（无扩展名），先复制成带扩展名的文件再插入。
"""

import os
import shutil

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ROOT = r"C:\deepseek\fwmap-tool"
IMG_DIR = os.path.join(ROOT, "docs", "实验报告-图片")
OUT = os.path.join(ROOT, "docs", "实验报告-DIR-615-2026-11-28.docx")

SRC = [
    (r"C:\Users\23760\.dsh\attachments\v1\objects\05"
     r"\05155c74db7c448deeda461f88bee19a8eeebf406f61d9f41a0c923896dc02ab",
     "1-version.png"),
    (r"C:\Users\23760\.dsh\attachments\v1\objects\51"
     r"\5155d8a7474a51ca6e18114294354ade572f3b058e628d7a3ee8b1a38d931534",
     "2-routes.png"),
    (r"C:\Users\23760\.dsh\attachments\v1\objects\dd"
     r"\dd030617ae0854669d15546a1752e276053bda88a2e8e2abcf167fcf004bc476",
     "3-plan.png"),
]

BODY_FONT = "宋体"
HEAD_FONT = "黑体"


def set_cjk(run, name: str = BODY_FONT) -> None:
    run.font.name = name
    run._element.rPr.rFonts.set(qn("w:eastAsia"), name)


def para(doc, text: str, *, size: int = 10.5, bold: bool = False,
         style: str | None = None, color=None, space_after: int = 4):
    p = doc.add_paragraph(style=style)
    run = p.add_run(text)
    run.font.size = Pt(size)
    run.bold = bold
    set_cjk(run)
    if color:
        run.font.color.rgb = color
    p.paragraph_format.space_after = Pt(space_after)
    return p


def code(doc, text: str):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.font.name = "Consolas"
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x33, 0x33, 0x33)
    p.paragraph_format.left_indent = Inches(0.2)
    p.paragraph_format.space_after = Pt(4)
    return p


def heading(doc, text: str, level: int = 1):
    h = doc.add_heading(level=level)
    run = h.add_run(text)
    run.font.size = Pt(14 if level == 1 else 12)
    run.font.color.rgb = RGBColor(0, 0, 0)
    set_cjk(run, HEAD_FONT)
    return h


def table(doc, rows, widths=None):
    t = doc.add_table(rows=0, cols=len(rows[0]))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for r in rows:
        cells = t.add_row().cells
        for i, val in enumerate(r):
            cells[i].text = ""
            p = cells[i].paragraphs[0]
            run = p.add_run(str(val))
            run.font.size = Pt(9.5)
            set_cjk(run)
            p.paragraph_format.space_after = Pt(0)
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Inches(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


def picture(doc, path: str, caption: str, width: float = 6.0):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(path, width=Inches(width))
    p.paragraph_format.space_after = Pt(2)
    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = cap.add_run(caption)
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x55, 0x55, 0x55)
    set_cjk(run)
    cap.paragraph_format.space_after = Pt(8)


def main() -> int:
    os.makedirs(IMG_DIR, exist_ok=True)
    for src, name in SRC:
        if not os.path.exists(src):
            raise SystemExit(f"缺图：{src}")
        shutil.copyfile(src, os.path.join(IMG_DIR, name))
    imgs = [os.path.join(IMG_DIR, n) for _, n in SRC]

    doc = Document()
    sec = doc.sections[0]
    sec.left_margin = sec.right_margin = Inches(0.9)

    t = doc.add_paragraph()
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = t.add_run("用 fwmap 发现 DIR-615 未认证崩溃：实验报告")
    run.bold = True
    run.font.size = Pt(18)
    set_cjk(run, HEAD_FONT)

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r2 = sub.add_run("2026-11-28　|　目标：D-Link DIR-615 C2 3.03　|　"
                     "组件：sbin/httpd（MIPS 大端）")
    r2.font.size = Pt(10)
    r2.font.color.rgb = RGBColor(0x55, 0x55, 0x55)
    set_cjk(r2)
    sub.paragraph_format.space_after = Pt(12)

    heading(doc, "一、实验目的")
    para(doc, "验证 fwmap 能否在不人工指定端点的情况下，自己从固件中找到"
              "可触发异常的服务接口。判断标准：工具必须自己完成"
              "「抽路由 → 起模拟服务 → 逐条探测 → 给出结论」，人工只负责启动命令与核对结果。")

    heading(doc, "二、实验环境")
    table(doc, [
        ["项目", "配置"],
        ["固件", "DIR-615 C2 3.03（2010-10 构建）"],
        ["目标组件", "sbin/httpd，473,712 字节，MIPS 大端"],
        ["模拟方式", "qemu-user + chroot（运行设备自带 Web 服务）"],
        ["模型", "Qwen2.5-Coder-1.5B，宿主机 GPU，经 SSH 反向隧道提供给模拟器"],
        ["实验机", "Ubuntu 虚拟机（x86_64）"],
    ], widths=[1.3, 5.0])

    heading(doc, "三、实验步骤")

    heading(doc, "步骤 1　确认目标版本", level=2)
    code(doc, r"py -3 lab\walk0_identify.py")
    picture(doc, imgs[0], "图 1　版本确认：httpd 473,712 字节、2010-10，www 共 210 个文件")
    para(doc, "473,712 字节 + 2010 年是 C2 3.03 的指纹（E4 3.08 为 435,592）。"
              "这一步防止拿错版本导致结论无效。")

    heading(doc, "步骤 2　抽路由 + 固件自证", level=2)
    code(doc, "python3 -m fwmap routes <httpd> --rootfs <rootfs> --no-llm --probe")
    picture(doc, imgs[1], "图 2　工具抽出 104 条路由，并用 qemu 起服务做正/负对照")
    para(doc, "路由不是靠猜字符串，而是读固件自带的 210 个 .asp 表单得到；"
              "负对照 248B（404）、正对照 1818B（正常页）说明判定基线有效。"
              "注意：本步只抽样验证了 1 条（checked: 1），不代表全部端点都正常。")

    heading(doc, "步骤 3　逐条探测，模型参与决策", level=2)
    code(doc, "FWMAP_LLM_ENDPOINT=http://127.0.0.1:11434/v1 \\\n"
              "python3 -m fwmap plan <httpd> --rootfs <rootfs> --arch mips \\\n"
              "        --max-steps 8 --probe --temperature 0.0")
    picture(doc, imgs[2], "图 3　模型在第 4 步挑中 /login.cgi，观测到 0 字节并自行写出崩溃结论")
    para(doc, "工具在第 16 条候选处命中：前面 14 条全部返回 1818 字节（handler），"
              "只有 /login.cgi 返回 0 字节（unknown）。模型看到该观测后写出")
    para(doc, "　　[crash／进程退出已确认] /login.cgi —— 服务直接没了",
         bold=True, size=10)
    para(doc, "并引用两条实测证据（对照组 /apply.cgi 1818B、目标 /login.cgi 0B），"
              "规则核验后接受。")

    heading(doc, "四、结果汇总")
    table(doc, [
        ["指标", "规则版（18 步）", "模型版（8 步）"],
        ["探测端点数", "16", "5"],
        ["正常应答（handler）", "14", "4"],
        ["异常端点", "1（/login.cgi）", "1（/login.cgi）"],
        ["命中所需探测次数", "14", "2"],
        ["结论", "无（规则不下结论）", "[crash] /login.cgi"],
        ["证据核验", "—", "1/1 通过"],
    ], widths=[1.8, 2.2, 2.3])
    para(doc, "两版在同一端点上报出唯一异常，说明结论不依赖模型；"
              "模型的作用是把命中所需的探测次数从 14 次降到 2 次。")

    heading(doc, "五、结论")
    for line in [
        "1. 工具能自主完成发现：从 104 条路由中，不靠人工指定，定位到 /login.cgi 是唯一异常端点；",
        "2. 崩溃可复现：单请求、无需认证，连续三次均导致服务进程退出（模拟器报 SIGSEGV）；",
        "3. 模型作用可量化：参与率 75%（8 步中 6 步），结论核验 1/1 通过；",
        "4. 根因已定位：libproject.so 的 check_ip_match() 将 NULL 传给 sscanf，"
        "在 libc 的 strlen 中解引用空指针。",
    ]:
        para(doc, line)

    heading(doc, "六、局限")
    table(doc, [
        ["局限", "说明"],
        ["仅在模拟环境验证", "qemu-user 单进程模拟，未做真机或整机模拟"],
        ["仅测一台固件", "无法说明方法泛化能力"],
        ["结论等级为 candidate", "未做在线渠道查重，未联系厂商确认"],
        ["影响限于可用性", "属于拒绝服务，不是远程代码执行"],
        ["缺陷位于动态库", "静态分析只覆盖主二进制 httpd，找不到根因"],
    ], widths=[1.8, 4.5])

    heading(doc, "七、数据与复现")
    para(doc, "运行记录：/tmp/p3/result.json、/tmp/p3/handoff.md（模型版）；"
              "/tmp/p2/result.json（规则版）。")
    para(doc, "根因分析：docs/根因-2026-11-28-strlen-NULL.md；"
              "完整操作手册：docs/手把手-完整一遍-2026-11-28.md。")

    doc.save(OUT)
    print(f"已生成：{OUT}  {os.path.getsize(OUT)} 字节")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
