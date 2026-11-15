"""图形界面 —— 给不想记命令的人用。

设计只有一句话：**选一个目录，按一个按钮。**

其余的事（挑哪个二进制、跑不跑 Ghidra、查不查 CVE、动不动 qemu）都由流水线
自己决定，界面上不出现。要调参的才去命令行。

两个按钮对应两种交付物：
- 「一键分析」= `autopilot`：工具自己决定下一步，最后给一段结论；
- 「完整报告」= `triage`：四层全跑，出一份能贴进报告的 HTML。

只用标准库（tkinter），不装任何东西。子进程一律带 PYTHONUTF8=1 ——
Windows 上不带的话，子进程按 GBK 输出，中文会变成一串问号（这个坑踩过）。
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "out"

# 子进程环境：和 plugins.py 同一个教训，UTF-8 必须显式给
def child_env(model: str = "") -> dict:
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    if model:
        env["FWMAP_LLM_MODEL"] = model
    return env


def build_cmd(mode: str, target: str, outdir: str, *, binary: str = "",
              port: int = 8080, llm: bool = False, limit: int | None = None,
              model: str = "", dyn: bool = False) -> list[str]:
    """把界面上的几个选项翻译成一条命令。

    抽成纯函数是为了能测 —— GUI 里的东西没法断言，命令拼错了却一定会出事。
    模型走环境变量 FWMAP_LLM_MODEL（triage 和 autopilot 都认），
    autopilot 另外还有 --llm-model，两处都给上，省得某个模式漏掉。
    """
    py = sys.executable
    if mode == "doctor":
        cmd = [py, "-m", "fwmap", "doctor"]
        if llm:
            cmd.append("--agent")
        return cmd
    if mode == "auto":
        cmd = [py, "-m", "fwmap", "autopilot", target, "--port", str(port)]
        if binary:
            cmd += ["--binary", binary]
        if llm:
            cmd.append("--llm")
            if model:
                cmd += ["--llm-model", model]
        if limit:
            cmd += ["--limit", str(limit)]
        cmd += ["-o", os.path.join(outdir, "survey.json")]
        return cmd
    if mode == "report":
        cmd = [py, "-m", "fwmap", "triage", target, "-o", outdir]
        if llm:
            cmd.append("--agent")
        if dyn:
            cmd += ["--dyn", "--dyn-check", "/tmp/pwned"]
        if limit:
            cmd += ["--limit", str(limit)]
        return cmd
    raise ValueError(f"未知模式：{mode}")


def looks_like_model(path: str) -> tuple[bool, str]:
    """模型目录至少要有 config.json；顺便提醒一下它得是完整下载的。"""
    p = Path(path)
    if not p.exists():
        return False, "这个目录不存在"
    if p.is_file():
        return False, "选的是文件，要选模型目录"
    if not (p / "config.json").exists():
        return False, "目录里没有 config.json —— 这不是 HuggingFace 格式的模型"
    big = [f for f in p.glob("*.safetensors")] or [f for f in p.glob("*.bin")]
    if not big:
        return False, "目录里没有 *.safetensors / *.bin —— 权重没下载完？"
    try:
        size = sum(f.stat().st_size for f in big) / (1 << 30)
    except OSError:
        size = 0
    if size < 0.2:
        return False, f"权重只有 {size:.1f} GB —— 太小，八成没下完"
    return True, f"{p.name}（{size:.1f} GB）"


# 上次选的模型记在这儿，下次打开不用再选
CFG_FILE = ROOT / "config.json"


def load_config() -> dict:
    try:
        with open(CFG_FILE, encoding="utf-8-sig") as fh:
            raw = fh.read()
        return json.loads(raw) if raw.strip() else {}
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict) -> None:
    """记不住就算了 —— 存配置失败不能挡住主流程。"""
    try:
        with open(CFG_FILE, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False, indent=2)
    except OSError:
        pass


def looks_like_rootfs(path: str) -> tuple[bool, str]:
    """快速判断选的东西像不像一个解包好的 rootfs。

    这里不追求严格，只为了在按错路径时早一点提示 —— 真正的判断由 `fwmap check` 做。
    """
    p = Path(path)
    if not p.exists():
        return False, "路径不存在"
    if p.is_file():
        if p.suffix.lower() in {".zip", ".bin", ".img", ".trx", ".chk", ".sqfs", ".squashfs"}:
            return False, ("这是个固件包，还没解包。请先在 Linux / WSL 上解包，"
                           "然后选解出来的目录（Windows 解 squashfs 会把符号链接弄成 0 字节）")
        return False, "这是一个文件，请选解包后的目录"
    names = {x.name for x in p.iterdir()}
    if {"bin", "etc"} & names or {"usr", "lib"} <= names:
        return True, ""
    return False, "这个目录里没有 bin/ 或 etc/，看起来不是解包后的 rootfs"


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("fwmap · 固件攻击面地图")
        self.geometry("1000x700")
        self.minsize(860, 560)
        self.q: queue.Queue = queue.Queue()
        self.proc: subprocess.Popen | None = None
        self.started_at = 0.0
        self.last_outdir = ""
        self.last_mode = ""
        self._build()
        self._prefill_model()
        self._tidy_out()

    def _prefill_model(self) -> None:
        """上次选的 → 环境变量 → 包内 tools/models → 常见缓存，尽量别让人重选。"""
        m = (load_config().get("model") or os.environ.get("FWMAP_LLM_MODEL") or "").strip()
        if not m or not Path(m).is_dir():
            try:
                from .agent.llm import find_model

                cand = find_model()
                m = cand if cand and Path(cand).is_dir() else ""
                # 同一目录下如果还有 7B，优先 7B：1.5B 只够跑通，判断质量差一截。
                # （config.json / 环境变量给的值在上一步就返回了，这里只管自动找。）
                if m:
                    with_7b = [p for p in Path(m).parent.glob("*7B*") if p.is_dir()]
                    if with_7b and "7B" not in Path(m).name:
                        m = str(sorted(with_7b)[0])
            except Exception:                                   # noqa: BLE001
                m = ""
        if m:
            self.model.set(m)
        self._validate_model(quiet=True)

    # ---------------------------------------------------------------- 界面
    def _build(self) -> None:
        ui = "Microsoft YaHei UI" if os.name == "nt" else "sans-serif"
        style = ttk.Style(self)
        try:
            style.configure("Big.TButton", font=(ui, 11, "bold"), padding=(14, 8))
        except tk.TclError:
            pass

        pad = ttk.Frame(self, padding=(16, 12))
        pad.pack(fill="both", expand=True)

        ttk.Label(pad, text="① 选固件（解包后的目录）", font=(ui, 11, "bold")).pack(anchor="w")
        row = ttk.Frame(pad)
        row.pack(fill="x", pady=(6, 2))
        self.target = tk.StringVar()
        ttk.Entry(row, textvariable=self.target, font=(ui, 10)).pack(
            side="left", fill="x", expand=True)
        ttk.Button(row, text="选择…", command=self._choose).pack(side="left", padx=(8, 0))

        self.hint = ttk.Label(pad, text="", foreground="#b42318", font=(ui, 9))
        self.hint.pack(anchor="w")

        opts = ttk.Frame(pad)
        opts.pack(fill="x", pady=(10, 4))
        ttk.Label(opts, text="② 选项（一般不用改）", font=(ui, 11, "bold")).pack(side="left")
        self.llm = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="用本地模型复核（慢，20 分钟起）",
                        variable=self.llm).pack(side="left", padx=(12, 0))
        self.dyn = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="动态验证（要 Linux）",
                        variable=self.dyn).pack(side="left", padx=(10, 0))
        ttk.Label(opts, text="  端口").pack(side="left")
        self.port = tk.IntVar(value=80)          # 和命令行默认值保持一致
        ttk.Spinbox(opts, from_=80, to=65535, width=7, textvariable=self.port).pack(side="left")
        ttk.Label(opts, text="  目标二进制").pack(side="left")
        self.binary = tk.StringVar()
        ttk.Entry(opts, textvariable=self.binary, width=16).pack(side="left")
        ttk.Label(opts, text="（留空=自动挑）", foreground="#667085").pack(side="left")

        mrow = ttk.Frame(pad)
        mrow.pack(fill="x", pady=(6, 0))
        ttk.Label(mrow, text="模型目录（可选）").pack(side="left")
        self.model = tk.StringVar()
        ttk.Entry(mrow, textvariable=self.model, width=64).pack(side="left", padx=(6, 6))
        ttk.Button(mrow, text="选择…", command=self._choose_model).pack(side="left")
        self.model_hint = ttk.Label(mrow, text="", foreground="#667085", font=(ui, 9))
        self.model_hint.pack(side="left", padx=(8, 0))
        self.model.trace_add("write", lambda *_: self._validate_model(quiet=True))

        ttk.Separator(pad).pack(fill="x", pady=10)

        btns = ttk.Frame(pad)
        btns.pack(fill="x")
        self.b_auto = ttk.Button(btns, text="③ 一键分析", style="Big.TButton",
                                 command=lambda: self._start("auto"))
        self.b_auto.pack(side="left")
        self.b_report = ttk.Button(btns, text="完整报告（HTML）", style="Big.TButton",
                                   command=lambda: self._start("report"))
        self.b_report.pack(side="left", padx=8)
        self.b_doctor = ttk.Button(btns, text="检查环境", command=lambda: self._start("doctor"))
        self.b_doctor.pack(side="left")
        self.b_stop = ttk.Button(btns, text="停止", command=self._stop, state="disabled")
        self.b_stop.pack(side="left", padx=8)
        self.b_report_open = ttk.Button(btns, text="打开报告", command=self._open_report,
                                        state="disabled")
        self.b_report_open.pack(side="right", padx=(8, 0))
        self.b_open = ttk.Button(btns, text="打开输出目录", command=self._open_out,
                                 state="disabled")
        self.b_open.pack(side="right")

        self.pb = ttk.Progressbar(pad, mode="indeterminate")
        self.pb.pack(fill="x", pady=(12, 6))
        self.pb.pack_forget()          # 空闲时不显示，免得看起来像一直在转

        logbox = ttk.Frame(pad)
        logbox.pack(fill="both", expand=True)
        self.log = tk.Text(logbox, wrap="none", font=("Consolas", 9), background="#0f172a",
                           foreground="#e2e8f0", insertbackground="#e2e8f0")
        ys = ttk.Scrollbar(logbox, orient="vertical", command=self.log.yview)
        xs = ttk.Scrollbar(logbox, orient="horizontal", command=self.log.xview)
        self.log.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.log.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        logbox.rowconfigure(0, weight=1)
        logbox.columnconfigure(0, weight=1)
        self.log.tag_configure("err", foreground="#fca5a5")
        self.log.tag_configure("ok", foreground="#86efac")
        self.log.tag_configure("info", foreground="#93c5fd")
        self.log.tag_configure("dim", foreground="#94a3b8")
        self.log.configure(state="disabled")

        self.status = tk.StringVar(value="选一个解包后的固件目录，然后按「一键分析」。")
        ttk.Label(pad, textvariable=self.status, font=(ui, 9),
                  foreground="#475467").pack(anchor="w", pady=(8, 0))

    # ---------------------------------------------------------------- 交互
    def _choose(self) -> None:
        p = filedialog.askdirectory(title="选解包后的固件目录")
        if p:
            self.target.set(p)
            self._validate()

    def _choose_model(self) -> None:
        p = filedialog.askdirectory(title="选模型目录（含 config.json 和 *.safetensors）")
        if p:
            self.model.set(p)
            self._validate_model()
            self._save_cfg()
            if self.llm.get():
                self.llm.set(True)           # 已经勾上了，保持勾上

    def _validate_model(self, quiet: bool = False) -> bool:
        path = self.model.get().strip()
        if not path:
            self.model_hint.configure(text="不填 = 只跑规则，结论一样", foreground="#667085")
            return True
        ok, msg = looks_like_model(path)
        if ok:
            note, colour = "", "#027a48"
            try:
                from .agent.llm import fit_model

                fits, why, alt = fit_model(path)
                if not fits:
                    note = f" · 用不了：{why}"
                    if alt:
                        note += f"，可改用 {Path(alt).name}"
                    colour = "#b42318"
                elif "偏紧" in why:
                    note = " · 内存偏紧，崩了就重试一次或先关掉别的程序"
                    colour = "#b45309"
            except Exception:                               # noqa: BLE001
                pass
            self.model_hint.configure(
                text=f"可以：{msg}{note} · 要用就勾上「用本地模型复核」", foreground=colour)
        else:
            self.model_hint.configure(text=msg, foreground="#b42318")
        if not ok and not quiet:
            messagebox.showwarning("模型目录不对", msg)
        return ok

    def _save_cfg(self) -> None:
        cfg = load_config()
        cfg["model"] = self.model.get().strip()
        save_config(cfg)

    def _validate(self) -> bool:
        ok, why = looks_like_rootfs(self.target.get().strip())
        self.hint.configure(text="" if ok else why)
        return ok

    def _start(self, mode: str) -> None:
        if self.proc:
            return
        target = self.target.get().strip()
        if mode != "doctor":
            if not target:
                messagebox.showwarning("还没选目标", "先选一个解包后的固件目录。")
                return
            if not self._validate():
                if not messagebox.askyesno("看起来不对", self.hint.cget("text") + "\n\n还是要试吗？"):
                    return

        model = self.model.get().strip()
        if self.llm.get():
            if not model:
                messagebox.showwarning(
                    "没选模型", "勾了「用本地模型复核」，但上面没选模型目录。\n\n"
                              "要么选一个（含 config.json 的目录），要么取消勾选 —— "
                              "不勾也能跑，结论一样。")
                return
            if not self._validate_model():
                return
            self._save_cfg()

        # 检查环境不产出任何文件，别为它建空目录（以前每点一次就留一个空壳）
        if mode == "doctor":
            self.last_outdir = ""
            self.last_mode = mode
        else:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            name = Path(target).name if target else "env"
            outdir = OUT_DIR / f"{name}-{mode}-{stamp}"
            try:
                outdir.mkdir(parents=True, exist_ok=1)
            except OSError:
                # 装在 Program Files 之类不可写的位置时，退到用户目录，别直接崩
                outdir = Path.home() / "fwmap-out" / f"{name}-{mode}-{stamp}"
                outdir.mkdir(parents=True, exist_ok=1)
            self.last_outdir = str(outdir)
            self.last_mode = mode

        cmd = build_cmd(mode, target, self.last_outdir or "", binary=self.binary.get().strip(),
                        port=int(self.port.get() or 8080), llm=bool(self.llm.get()),
                        model=model, dyn=bool(self.dyn.get()))
        self._log_clear()
        self._log(f"$ {' '.join(cmd)}\n", "dim")
        if self.last_outdir:
            self._log(f"输出目录：{self.last_outdir}\n\n", "dim")
        if model:
            self._log(f"模型：{model}\n\n", "dim")
        self.started_at = time.time()
        self._busy(True)

        def work() -> None:
            try:
                p = subprocess.Popen(cmd, cwd=str(ROOT), env=child_env(model),
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, encoding="utf-8", errors="replace",
                                     bufsize=1)
                self.proc = p
                for line in p.stdout:                       # type: ignore[union-attr]
                    self.q.put(("line", line))
                code = p.wait()
                self.q.put(("done", code))
            except Exception as e:                          # noqa: BLE001
                self.q.put(("line", f"[!] 起不来：{e}\n"))
                self.q.put(("done", -1))

        threading.Thread(target=work, daemon=True).start()
        self.after(80, self._poll)

    def _stop(self) -> None:
        p = self.proc
        if not p:
            return
        self._log("\n[!] 正在停止…\n", "err")
        try:
            if os.name == "nt":
                # 只杀这一棵进程树：Ghidra 会再起 java 子进程，光 terminate 杀不干净
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"],
                               capture_output=True)
            else:
                p.terminate()
        except Exception:                                   # noqa: BLE001
            pass

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "line":
                    tag = "dim"
                    if payload.startswith(("[!]", "[x]", "Traceback", "ERROR")):
                        tag = "err"
                    elif payload.startswith("[+]"):
                        tag = "ok"
                    elif payload.startswith("[*]"):
                        tag = "info"
                    self._log(payload, tag)
                    self.status.set(payload.strip()[:120] or self.status.get())
                else:
                    self._finish(payload)
                    return
        except queue.Empty:
            pass
        self.after(120, self._poll)

    def _finish(self, code: int) -> None:
        self.proc = None
        self._busy(False)
        self.pb.stop()
        self.pb.pack_forget()
        secs = time.time() - self.started_at
        report = self._find_report()
        # doctor 的退出码 1 表示「有缺项」，不是失败 —— 别把红色警告当成程序崩了
        missing = self.last_mode == "doctor" and code == 1
        if code == 0 or missing:
            tail = "（有缺项，看上面的 [MISS] 行）" if missing else ""
            where = f"。输出在 {self.last_outdir}" if self.last_outdir else ""
            self.status.set(f"完成，用时 {secs:.0f} 秒{tail}{where}")
            self._log(f"\n[+] 完成，用时 {secs:.0f} 秒{tail}\n",
                      "err" if missing else "ok")
            if report:
                self._log(f"[+] 报告：{report}\n", "ok")
        else:
            self.status.set(f"退出码 {code}，用时 {secs:.0f} 秒 —— 看上面的日志")
            self._log(f"\n[!] 退出码 {code}\n", "err")
            # Windows 上原生崩溃的退出码，光看数字没法猜。最常见的那个其实是内存不够：
            # 加载大模型时 PyTorch/bitsandbytes 不抛异常，直接访问违例杀掉进程。
            hint = {
                3221225477: ("0xC0000005 访问违例。加载大模型时内存不足最常见 —— "
                             "换小一点的模型（同目录的 1.5B），或者不勾「用本地模型复核」。"),
                3221225725: "0xC00000FD 栈溢出。",
                3221225781: "0xC0000135 找不到 DLL —— agent 依赖没装好（torch/bitsandbytes）。",
            }.get(code)
            if hint:
                self._log(f"    {hint}\n", "err")
        self.b_report_open.configure(state="normal" if report else "disabled")

        # 一键分析以前只出 survey.json，屏幕上就几行滚动的字 —— 太容易让人觉得「没跑」。
        # 跑完弹一个结论框，顺便把结论页（survey.html）亮出来。
        if code == 0 and self.last_mode == "auto":
            self._show_summary()
        if code != 0:
            self._cleanup_empty_run()

    def _cleanup_empty_run(self) -> None:
        """这次什么都没产出（崩了/秒退），别留一个空目录占着位置。"""
        if not self.last_outdir:
            return
        try:
            p = Path(self.last_outdir)
            if p.is_dir() and not any(p.rglob("*")):
                p.rmdir()
                self._log(f"[i] 这次没有产出文件，空目录已删除：{p.name}\n", "dim")
                self.last_outdir = ""
        except OSError:
            pass

    def _tidy_out(self, hours: int = 1) -> None:
        """清掉老的空目录（只删空的、且创建超过 N 小时的）。

        为什么要按时间筛：正在跑的分析会先建目录、最后才写文件，
        这时候它看起来就是空的 —— 不能顺手删掉。
        """
        removed = 0
        try:
            for p in OUT_DIR.iterdir() if OUT_DIR.is_dir() else []:
                if not p.is_dir():
                    continue
                try:
                    age_h = (time.time() - p.stat().st_mtime) / 3600
                except OSError:
                    continue
                if age_h < hours:
                    continue
                try:
                    if not any(p.rglob("*")):
                        p.rmdir()
                        removed += 1
                except OSError:
                    pass
        except OSError:
            return
        if removed:
            self._log(f"[i] 清掉了 {removed} 个历史空目录\n", "dim")

    def _summary_text(self) -> str:
        """从 survey.json 取结论，拼成能直接读的一段话。"""
        path = Path(self.last_outdir) / "survey.json" if self.last_outdir else None
        if not path or not path.exists():
            return ""
        try:
            with open(path, encoding="utf-8-sig") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return ""
        lines = [str(x) for x in (data.get("lines") or [])]
        if not lines:
            return ""
        return ("\n".join("· " + x for x in lines)
                + "\n\n（「打开报告」能看这一页；逐条链的明细用「完整报告」。）")

    def _show_summary(self) -> None:
        text = self._summary_text()
        if not text:
            return
        self._log("\n" + text + "\n", "ok")
        try:
            messagebox.showinfo("分析完成", text)
        except tk.TclError:
            pass

    def _find_report(self) -> str:
        """在输出目录里找 report.html —— 有它才让「打开报告」可点，不猜路径。"""
        if not self.last_outdir or not os.path.isdir(self.last_outdir):
            return ""
        for dirpath, _dirs, files in os.walk(self.last_outdir):
            for name in files:
                if name.lower().endswith(".html"):
                    return os.path.join(dirpath, name)
        return ""

    def _busy(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        for b in (self.b_auto, self.b_report, self.b_doctor):
            b.configure(state=state)
        self.b_stop.configure(state="normal" if running else "disabled")
        self.b_open.configure(state="normal" if self.last_outdir else "disabled")
        if running:
            self.b_report_open.configure(state="disabled")
            self.pb.pack(fill="x", pady=(12, 6), before=self.log.master)
            self.pb.start(12)

    def _open_out(self) -> None:
        if not self.last_outdir or not os.path.isdir(self.last_outdir):
            return
        try:
            os.startfile(self.last_outdir)                  # type: ignore[attr-defined]
        except AttributeError:
            subprocess.run(["xdg-open", self.last_outdir])
        except Exception:                                   # noqa: BLE001
            messagebox.showinfo("输出目录", self.last_outdir)

    def _open_report(self) -> None:
        path = self._find_report()
        if not path:
            return
        try:
            os.startfile(path)                              # type: ignore[attr-defined]
        except AttributeError:
            subprocess.run(["xdg-open", path])
        except Exception:                                   # noqa: BLE001
            messagebox.showinfo("报告路径", path)

    # ---------------------------------------------------------------- 日志
    def _log(self, text: str, tag: str = "") -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text, tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _log_clear(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")


def run(argv=None) -> int:
    try:
        app = App()
    except tk.TclError as e:
        print(f"[!] 打不开窗口（{e}）。没有图形环境时请用命令行：python -m fwmap autopilot <rootfs>")
        return 2
    if argv:
        app.target.set(str(argv[0]))
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
