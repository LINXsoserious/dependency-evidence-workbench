# 数据来源与许可

## 协议

- 批量匹配：[OSV POST /v1/querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)。响应按请求顺序映射；分页令牌属于单项查询。
- 公告详情：[OSV GET /v1/vulns/{id}](https://google.github.io/osv.dev/get-v1-vulns/)。保留原始公告 ID、别名与修改时间。

## 演示数据

`samples/osv-snapshot.json` 由 `scripts/refresh_demo.py` 从公开 API 获取，不是模型生成的漏洞内容。文件中 `captured_at` 记录获取时间，`queries` 记录示例版本的匹配结果，`records` 保存原始公告对象。应用据此生成排序、合并和摘录，原始对象未翻译或改写。

- GHSA 公告：GitHub Advisory Database，数据与贡献者信息见 https://github.com/github/advisory-database ，许可见 https://github.com/github/advisory-database/blob/main/LICENSE.md 。
- PYSEC 公告：PyPA Advisory Database，数据与贡献者信息见 https://github.com/pypa/advisory-database ，许可见 https://github.com/pypa/advisory-database/blob/main/LICENSE 。
- 两者公告资料按 Creative Commons Attribution 4.0 International 保留署名。完整许可文本位于 `LICENSES/CC-BY-4.0.txt`。
- 每条公告还保留其 references、affected 数据与 OSV 原始记录链接，可继续追溯相关项目的原始说明。来源方不为本工具提供背书。

程序代码的 Apache-2.0 许可证不替换公告数据自身的许可证。自行刷新或替换数据源时，应同时核对新的来源与许可。
