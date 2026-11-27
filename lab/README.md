# 瀹為獙鑴氭墜鏋讹紙鏈湴 lab 鐢紝涓嶆槸宸ュ叿鐨勪竴閮ㄥ垎锛?
杩欎簺鑴氭湰鏄?*鍋氬疄楠屾椂鐨勬墜杈瑰伐鍏?*锛屼笉鏄?`fwmap` 鍖呯殑涓€閮ㄥ垎锛屼篃涓嶅弬涓庢墦鍖呫€?鏀捐繘鏉ユ槸鍥犱负锛氭崲鍙版満鍣ㄧ户缁仛瀹為獙鏃讹紝娌℃湁瀹冧滑灏卞緱浠庡ご閲嶅啓涓€閬嶈繛鎺ュ拰鍚屾閫昏緫銆?
> 鈿狅笍 閲岄潰鐨?`HOST / USER / PWD`锛坄192.168.8.137` / `ubuntu` / `ubuntu`锛?> 鏄?*鏈湴瀹為獙铏氭嫙鏈?*鐨勫湴鍧€鍜屽彛浠わ紝鎹㈢幆澧冭鍏堟敼杩欎笁琛屻€?
## 鏂囦欢璇存槑

| 鏂囦欢 | 浣滅敤 |
|---|---|
| `vm.py` | SSH 鎵ц鍛戒护鐨勮杽灏佽锛坄run(cmd, timeout, sudo)`锛?|
| `vm_do.py` | 鍛戒护琛岀増锛歚py -3 vm_do.py [--sudo] <bash 鍛戒护>` |
| `vm_put_run.py` | 鎶婃湰鍦拌剼鏈紶涓婂幓鍐嶈窇锛岃緭鍑哄瓨鎴?`<鏂囦欢鍚?.out`锛圲TF-8锛?|
| `vm_sync.py` | 鎶婃暣涓粨搴撴墦鍖呭悓姝ュ埌 VM 鐨?`/home/ubuntu/fwmap-run` |
| `llm_tunnel.py` | **鍙嶅悜** SSH 闅ч亾锛歏M 鐨?`127.0.0.1:11434` 鈫?瀹夸富鏈虹殑 `fwmap serve` |
| `llm_ping.py` | 浠?VM 閲屾帰涓€涓?LLM 绔偣閫氫笉閫?|
| `fetch_plan.py` | 鍙栧洖 `fwmap plan --json` 鐨?trace 骞舵墦鍗版憳瑕?|
| `plan_d615.sh` | 鍦?VM 閲岃窇 DIR-615 鐨?agent 寰幆锛堝甫鎺㈤拡锛?|
| `plan_d615_nollm.sh` | 鍚屼笂锛宍--no-llm` 瀵圭収缁?|
| `run5.sh` | 鍚屼竴鍥轰欢杩炶窇 5 娆★紝姹囨€昏嚜璇勮〃锛坄temp=0`锛?|
| `run5t.sh` | 娓╁害缁勶紙`--temperature 0.7`锛夛紝涓庡墠鑰呭苟鎺掓瘮杈?|
| `run5a.sh` | 鍖垮悕缁勶紙`--anonymize`锛夛紝娴嬨€岄潬鍚嶅瓧杩樻槸闈犺涓恒€?|

## 鍏稿瀷鐢ㄦ硶

```bash
# 1) 瀹夸富鏈猴細鎶婃湰鏈烘ā鍨嬫寕鎴?OpenAI 鍏煎鎺ュ彛
python -m fwmap serve --port 11434

# 2) 瀹夸富鏈猴細寮€鍙嶅悜闅ч亾锛圴M 鐨?sshd 鍙嶅悜杞彂鍥炴潵锛屼笉鐢ㄥ姩闃茬伀澧欙級
python lab/llm_tunnel.py

# 3) 瀹夸富鏈猴細鎶婁粨搴撳悓姝ュ埌 VM
python lab/vm_sync.py

# 4) 鍦?VM 閲岃窇涓€杞紙鑴氭湰鍐呴儴宸茶缃?FWMAP_LLM_ENDPOINT锛?python lab/vm_put_run.py lab/plan_d615.sh "bash"

# 5) 杩炶窇 5 娆?+ 鑷瘎姹囨€?python lab/vm_put_run.py lab/run5.sh "bash"
```

## 涓や釜韪╄繃鐨勫潙锛堝啓鍦ㄨ繖閲屽厤寰楀啀韪╋級

1. **闅ч亾閲屼笉鑳界粰 socket 璁?timeout**锛氭ā鍨嬩竴娆℃帹鐞?20 绉掍互涓婏紝瓒呮椂浼氭妸杩炴帴鍏虫帀锛?   鏈嶅姟绔洖鍖呮椂鎶?`WinError 10053`銆?2. **`vm_sync.py` 瑕佸厛 `sudo rm -rf` 鐩爣鐩綍**锛氫笂涓€杞槸鐢?sudo 璺戠殑锛?   鐩綍閲屽叏鏄?root 鐨勬枃浠讹紝鏅€氱敤鎴峰垹涓嶆帀銆佷篃瑕嗙洊涓嶄簡銆?