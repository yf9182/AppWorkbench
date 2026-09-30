# AppWorkbench

通过当前 Codex 对话调查产品、推荐版本并交付经确认的迭代。支持单 App、纯网站、多仓库产品和共享后端。Python CLI 保存可恢复状态，Codex Skill 组织工作，查看面板只展示结果。

## 开始使用

本机默认代码目录 `~/AppWorkbench`，运行入口 `bin/wb`。迁移代码目录时可设置 `APP_WORKBENCH_CODE` 供 Skill 定位；`APP_WORKBENCH_HOME` 默认 `~/.config/app-workbench`，保存产品清单、SQLite、报告、证据和凭据。代码仓库不保存业务数据或秘密。

```sh
./bin/wb --help
./bin/wb init
./bin/wb product list
./scripts/install-skill.sh
```

安装脚本将 Skill 链接到 `${CODEX_HOME:-$HOME/.codex}/skills/app-workbench`，重复执行无副作用，已有不同 Skill 时拒绝覆盖。Codex 未发现新 Skill 时，在新对话中显式调用 `$app-workbench` 或按当前客户端说明刷新技能发现。

可以说：

- “看看 AI Pet Studio 最近的情况，推荐下一版。”
- “按这份已登记的计划执行。”
- “查看这个版本进度，继续未完成的步骤。”
- “这个 TestFlight 版本我测试了，反馈如下……”

调查后先呈现一个具体计划。你确认的计划修订才授权该产品的开发和交付；框架实现不会替代两个试点产品各自的版本确认。网站与后端经过测试、独立评审和门禁后可 PR 合并、部署及冒烟；iOS 支持归档、TestFlight 与正式准备，提审和发布仍由你操作。

## 接入与运维

- [工作流程](docs/workflow.md)：命令、版本确认、证据、恢复和迁移。
- [验收要求](docs/acceptance.md)：框架、候选、真人业务验收和实际试点。
- [实现接口](docs/architecture.md)：适配器及持久化行为。
- [Skill](skills/app-workbench/SKILL.md)：自然语言请求的执行规则。
- `templates/`：调查、计划及 JSON 证据的 authoring 示例；示例不构成证据，实际字段以 CLI 为准。

已有凭据中心的 `products.json` 作为产品登记来源，平台凭据使用 `manifest.json` 中的标识。新增普通产品配置仓库、目标、检查、依赖、预算与运营目标即可；新平台通过适配器增加。缺代码或目标配置不一致的项目保留为待接入，不假定可部署。

CalorieSnapshot 复用原运营脚本、状态和签名工具。接管前查明旧执行者；同一产品只允许一个开发发布执行者，保留已有运行历史。AI Pet Studio 串联 iOS/Web/Backend，先调查 Analytics SDK 与分发配置缺口，再由确认的迭代处理。

不新建自主选题或定时运营，不自动切换付费模型 API。最多三个 Agent（含协调者），继承当前对话设置；子 Agent 不派生。测试只跑受改动影响的必要集；真实云写入、真机购买和人工验收需各自实际证据，单元测试不能代替。

## 备份

用 `bin/wb backup --help`、`restore --help` 备份运行状态与报告；凭据继续通过外部 `scripts/wb-credentials` 加密迁移。密钥与加密包分开传输。恢复后重新核验 GitHub/Codex/Xcode 会话、签名和目标身份，不沿用本机签名完成标记冒充新机就绪。

## 运行环境与真实验收

`bin/wb` 优先使用 Codex 已有 Python（含 cryptography）、Node 和工具目录，也可用 `APP_WORKBENCH_PYTHON` / `APP_WORKBENCH_RUNTIME` 指定环境。产品的 npm/npx/Xcode/gh/Wrangler 与依赖需实际存在；配置入口不代表这些检查已经通过。缺平台或发布映射的项目只登记源码目标，不允许发布。

```sh
./bin/wb product inspect ai-pet-studio
./bin/wb collect ai-pet-studio --days 7
./bin/wb iteration create ai-pet-studio --plan /absolute/path/plan.md
./bin/wb serve --port 8765
```

备份状态与凭据分别加密；先恢复状态至新目录，将凭据中心包先恢复到一个独立的新临时目录，再以 `wb restore --credential-home /absolute/path/to/restored-credentials` 合并到最终新目录。产品清单和 SQLite 来自状态包，凭据文件和维护工具来自凭据包。不能让两个恢复工具覆盖彼此的既有目录。产品归档/导出等绝对路径迁移后重新登记并确认受影响计划。

归档每次使用新的输出目录；上传要求对应提交真实导出的 IPA。新增 IPA 文件引用保留同一提交的代码测试与独立评审，签名和制品身份仍在上传前实际检查。历史发布记录不能放行另一份计划或另一套目标配置。
