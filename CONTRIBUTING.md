# 贡献指南

感谢关注 VC-Strike！贡献前请先阅读：

## 前提

1. **授权背景**：涉及利用逻辑的 issue/PR，请说明你的授权场景
   （自建实验环境 / 客户授权渗透 / 防御研究）。与漏洞利用无关的
   bug 修复、文档、UI 改进无需说明。
2. **安全边界**：不接受以下方向的贡献（见 README 安全边界一节）：
   ESXi 破坏类操作、隐蔽持久化/beacon、免杀与检测规避。

## 开发

```bash
git clone https://github.com/chu0119/vc-strike.git
cd vc-strike
python -m vcstrike selftest            # 必须全绿
python -m unittest discover -s tests   # 必须全绿
python vc-strike.py                    # GUI 冒烟
```

- 目标：Python 3.8+，**仅标准库**（新增依赖需在 issue 中讨论）。
- 纯 Python AES / BER / SRP 属于协议保真实现，修改前请阅读
  `vcstrike/aes128.py`、`vcstrike/srp59309.py` 的注释与
  `docs/漏洞分析.md`，并保持 `selftest` 的 FIPS-197 向量通过。
- 新功能请同时提供 CLI 子命令与 GUI 入口（保持二者能力等价）。

## 提交

- 分支：`feat/xxx`、`fix/xxx`、`docs/xxx`。
- Commit 信息：中英文均可，说明动机与影响。
- PR 请附带：改动说明、自检/测试输出、（涉及利用时）验证环境说明。

## 报告工具自身的安全问题

见 [SECURITY.md](SECURITY.md)。
