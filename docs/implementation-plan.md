# 依赖漏洞核验工作台 v0.1

日期：2026-10-26。用户要求继续制作 GitHub 作品，强调成果可用性；沿用免费、免绑卡与 LINXsoserious 发布账号。

## 设计决策

输入真实依赖清单，输出可追溯的漏洞与修复参考，而不把三个固定 CVE 的演示当成通用问答产品。采用 OSV 公开 API，由服务按生态、包名和精确版本匹配；不安装或执行上传的依赖。

首版支持 Python 精确锁定的 requirements 文本、pip list JSON、npm package-lock v2/v3。范围约束、嵌套文件、URL 依赖、无法确定的版本必须列入未解析项。未命中、未解析、查询失败、仅命中撤回公告必须分开。公告别名合并，但保留每个受影响的依赖版本。

双入口：Streamlit 网页供交互复核，CLI 供日常检查与 CI 使用。网络查询只发送用户选定的生态、包名和版本；公开公告缓存与依赖清单分离。应用无需模型或账号。它是确定性安全工具，本版不自称 RAG 或自主 Agent。

## 文件与任务

- [x] `dependency_workbench/manifests.py`：有界解析、去重、显式未解析项；测试精确版本、标记、嵌套 npm 与输入上限。
- [x] `dependency_workbench/osv.py`：OSV 批量查询、每项分页、错误隔离、限时、公开公告缓存；测试失败不能变成零命中。
- [x] `dependency_workbench/report.py`：别名合并、分支修复边界、撤回处理、JSON / Markdown / CSV 导出；测试不跨包挪用修复版本。
- [x] `dependency_workbench/cli.py`：离线与联网扫描，退出码 0=完整且未命中、1=完整且命中、2=不完整或错误。
- [x] `app.py`：清单预览、生产依赖筛选、排除包名、真实快照演示、明确的联网按钮、漏洞过滤与原始证据、下载报告。
- [x] `scripts/refresh_demo.py`：从真实公开 API 获取演示快照，记录获取时间、来源和数据许可；演示与实时查询严格区分。
- [x] `tests/`、CI 配置、README、来源与许可、截图、启动脚本和完整 ZIP：验证本地源码与交付包，发布后以 Actions 实际结果核验云端测试。

## 接口与验收

`parse_manifest(data, filename)` 返回唯一 Dependency 列表与未解析清单；`OSVClient.query(packages)` 返回按输入映射的每项结果；`scan(parsed, client)` 生成报告。查询分页继续传入原包和版本，不使用失去位置的全局索引。详情获取失败时保留命中 ID，并将报告标为不完整。

实际验证至少包含一份有已知漏洞的公开示例、一份真实项目依赖清单、断网/失败路径，以及 CLI 和网页导出。不存在的公网演示、未运行的模型或用户独立能力不写成已完成成果。


本地源码与配置已完成；公开仓库为 LINXsoserious/dependency-evidence-workbench。云端 CI 状态以该仓库 Actions 的实际运行为准。
