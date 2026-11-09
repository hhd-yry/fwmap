"""回归测试：传播器赋值必须**覆盖**旧污染，否则归因会错。

真实案例（DIR-842 cgibin / FUN_0041b438）：
    local_22c = getenv("HTTP_SOAPACTION");
    pcVar1    = getenv("HTTP_HNAP_AUTH");     <- 先标脏 HNAP_AUTH
    pcVar1    = strrchr(local_22c, '/');      <- 换成了 SOAPACTION 的一段
    FUN_0041af78(pcVar1, ...) -> sprintf(acStack_108, "%s%s", "/runtime/hnap/", pcVar1)
工具曾经报 "HNAP_AUTH -> sprintf"，实际进 sprintf 的是 SOAPACTION。
"""
import os
import sys

# 用包所在目录，而不是写死的开发路径（换机器/换目录也能跑）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fwmap.m3flow import analyze_c, _load_catalog          # noqa: E402
from fwmap.m3 import catalog_path                          # noqa: E402

SRC = """
undefined4 FUN_test(undefined4 param_1)
{
  char *pcVar1;
  char *local_22c;
  char acStack_108 [256];

  local_22c = getenv("HTTP_SOAPACTION");
  pcVar1 = getenv("HTTP_HNAP_AUTH");
  pcVar1 = (char *)strrchr(local_22c,0x2f);
  sprintf(acStack_108,"%s%s","/runtime/hnap/",pcVar1);
  return 0;
}
"""

sources, sinks, weak = _load_catalog(catalog_path())
hits = analyze_c("FUN_test", "0x0", SRC, sources, sinks, weak)

print(f"命中 {len(hits)} 条:")
ok = False
for h in hits:
    print(f"  {h['source_api']}({h['source_param']}) -> {h['sink']} via={h['via']}")
    if h["sink"] == "sprintf" and h["source_param"] == "HTTP_SOAPACTION":
        ok = True

print()
if ok:
    print("PASS：归因是 HTTP_SOAPACTION（新值），不是 HTTP_HNAP_AUTH（旧值）")
else:
    print("FAIL：归因仍然错，检查 _propagate_through_calls 是否还用了 setdefault")
    raise SystemExit(1)
