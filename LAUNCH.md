# LAUNCH · VeriCode (Phase 8)

> Written to read like a human wrote it, not marketing copy. **All publish/posting
> actions are gated (⛔) — nothing below has been executed.**
>
> **修订 2026-11-13**：核对社区自我推广规则后发现原稿两处错误 —— `r/programming`
> 明令禁止项目 demo / "I made this" 求反馈帖；`r/opensource` 对 AI 项目与不足 3 个月的
> 新项目有限制。原稿中「10 CVEs」也没有任何运行输出支持，已删除。
> 完整取证与裁决见工作区 `phase8/SELF-PROMO-RULES.md`。
> **目前唯一用一手规则核对、确定合规的渠道是 Show HN；Reddit 两版为待核对草稿，未获放行。**

## The honest pitch
I built VeriCode because I kept pasting AI-generated code into repos and only
*hoping* it worked. `vericode .` runs the checks that should've been obvious —
type-check, tests, secret scan, dependency CVEs — in one local command, no
account, no config. In a throwaway sample it caught a hardcoded Stripe key
(captured in `QA.md`). It's small, it's MIT, and the scanner is dependency-free.

---

## Show HN
**Title:** Show HN: VeriCode – verify AI-generated code actually works, in one local command

**First post:**
> I've been using coding agents a lot this year, and my recurring mistake is
> trusting code that *looks* right. So I built a tiny CLI that runs the "should've
> been obvious" checks before I commit: type-check, tests, hardcoded-secret scan,
> and a dependency CVE lookup.
>
> It's local-first and keyless — the CVE check hits the free OSV API anonymously,
> nothing leaves your machine otherwise. `vericode .` prints a table;
> `vericode . --strict` is the CI gate (non-zero exit on any problem).
>
> What I'm unsure about: is "one command for all of it" actually useful, or do
> people already have this wired up with separate tools? And the type-check/test
> steps intentionally *skip* (not pass) when the toolchain isn't installed, so it
> never lies about being green. Curious if that's the right call.
>
> MIT, Python. Would love feedback on what's missing.

**规则核对（一手，https://news.ycombinator.com/showhn.html）**：
- 合规点：是自己做的、别人能 `pip install -e .` 后立刻试、无注册门槛、标题以 `Show HN` 开头、
  正文讲了 why 和「哪里还不完美」。这段质疑要保留，别改成营销腔。
- 硬性要求：**发帖当天作者必须在评论区回答问题**。
- 官方明令「Please don't ask friends to upvote or comment」——不拉票、不互赞、不刷 Star。
- 不要附落地页 / 募捐页 / 纯博客文章；小版本更新也不够格。

---

## Reddit — 两版草稿，**均未获放行**

> 诚实前提：本环境直取 Reddit 官方 `about/rules.json` 被 403 拦截，以下依据的是多个二手来源
> 交叉印证（详见 `phase8/SELF-PROMO-RULES.md`），**发帖前必须由人打开当期官方 rules 页复核**。
> 版主有最终解释权。

### ~~r/programming~~ —— **撤下，不得发布**

多个独立来源一致：该版禁止 product promotion、「I Made This」project demo、以及求反馈帖；
只有实质性技术文章可能合规。原稿标题 `I made a CLI that...` 正是被禁形态。
若想覆盖这个社区，只能写另一篇讲设计取舍的技术文章（例如 zero-config 多语言检查、
"skip ≠ pass"），且不以引流为目的 —— 那不属于本次发布计划。

### r/opensource — 走 weekly New Project Megathread（唯一可能合规的路径）

项目发布才 3 天，通用规则是「不足 3 个月只能进当期 New Project Megathread」；
该版另有 AI 相关项目受限、`Promotional` flair、推广占比约 10% 等说法（来源互相有冲突）。
不要发独立项目帖。

> **Megathread 留言草稿（按当期模板调整）**
> VeriCode — a local CLI that runs type-check, tests, secret scan and a keyless OSV
> CVE lookup on AI-generated code in one command (`vericode .`). MIT, Python 3.9+,
> zero-config, ~40 tests. Looking for contributors: the repo has 5 `good first issue`
> items. Honest caveat: toolchain-missing checks report *skip*, not *pass*, and the
> CVE lookup degrades to an empty result on network errors — that's the part I'd
> most like help with. Repo: https://github.com/LucasXlab/vericode

### r/trueopensource — 第二版草稿，**证据弱，须先核规则**

一个二手来源称该社区由 `r/opensource` 的 AI 项目禁令分裂而来、允许标注后的 AI 项目。
本流水线**未取到其官方规则，不背书这个社区**；仅提供草稿备查，核规则前不要发。

> Title: VeriCode: one local command to check whether AI-written code actually runs
> Body: short version of the Show HN post. Lead with the "skip ≠ pass" decision and
> the OSV-failure caveat rather than feature list. Say plainly that it's 3 days old,
> 40 tests, MIT, and ask what the first additional ecosystem should be.
> Link repo + license. One post only, reply to every comment.

---

## X / Twitter — 5-tweet thread
1/ I pasted AI-generated code into a repo and it *looked* fine. It had a hardcoded
Stripe key in a throwaway sample. Built a tiny CLI so I'd stop doing that: `vericode .`

2/ One command: type-check, run tests, scan for secrets, check dependency CVEs.
No account, no config, nothing leaves your machine (CVE lookup is keyless + anonymous).

3/ `vericode . --strict` is the CI gate — non-zero exit on any problem. Drop it
into GitHub Actions in 3 lines.

4/ Design choice I'm stubborn about: if the toolchain (mypy, tsc, go…) isn't
installed, it reports *skip*, never *pass*. A green check you didn't earn is worse
than no check.

5/ MIT, Python, ~400 lines of real logic + tests. Feedback welcome — especially
what's missing. (link)

---

## Product Hunt tagline
> VeriCode — Verify AI-generated code actually works: type-check, test, secret-scan
> and CVE-check in one local command. No account, no config.

---

## 中文版

### 掘金
标题：我用 AI 写代码踩的坑：它看起来对，其实藏着一个硬编码密钥
正文：同 Show HN 故事线，强调"本地优先、零配置、免密钥查 CVE"，附
`vericode . --exclude tests` 的真实输出截图。结尾抛问题：你现在的
AI 代码准入流程是什么？发前核对掘金自荐/推广规则。

### V2EX
标题：[开源] VeriCode —— 一条命令验证 AI 生成的代码到底能不能用
正文：短，突出"skip 不等于 pass"的设计取舍，问大家第一个该加什么语言/生态。
建议发「分享创造」节点；遵守 V2EX 自荐版规：一次、附 GitHub 链接、回帖。

### 即刻
一条动态：用 3 句话讲清痛点 + 一条命令 + 链接，带 #独立开发 #AI编程 话题。

---

## 发布时间建议（按社区活跃时段，UTC+8）
- **Show HN / Hacker News:** 周二–周四 22:30–24:00（美西早间，HN 流量高峰）—— **唯一已核对合规的渠道**
- **X / Twitter:** 与 Show HN 同日稍后发 thread，隔 30–45 分钟逐条发
- **掘金 / V2EX / 即刻:** 周四–周六 20:00–22:00（国内开发者活跃）；发前核对各站版规
- **Reddit 两版：** 规则核对完成前**不排时段**；核对通过后再按当期 megathread 周期安排
- 错峰，不一次性全平台铺开，便于逐个社区认真回帖。

## 发布后 72 小时响应清单
- [ ] **先处理已经来的人**：批准 3 个 `action_required` 的外部 PR CI，逐个 review 4 个 OPEN PR
      （`#7` OSV 缓存 / `#8` 单文件扫描 / `#9` HCL 规则 / `#10` `--version`）
- [ ] 修 Issue #4 报出的真实 bug：`--exclude` 只排除精确文件路径、不排除目录
- [ ] 每个帖子/Issue/PR 认真回复，尤其是质疑（"已有 gitleaks/Snyk" → 说明差异表）
- [ ] 收集反馈进 `docs/initial-issues.md` 或新 Issue
- [ ] 快速修 bug（CI 红了立刻修，保持 main 常绿）
- [ ] 对"skip ≠ pass"、CVE 查询失败会静默降级这两个问题准备标准答案
- [ ] 72h 后汇总 Star 增长、流量来源、高频反馈 → 写入 `RETRO.md`（阶段 9）

---

## ⛔ 当前真实状态与待确认动作

**已由并行会话执行（本会话未授权、未执行，此处仅记录事实）：**
1. ~~`gh repo create LucasXlab/vericode --public`~~ — 仓库已公开，创建于 2026-11-10T07:12:14Z
2. ~~提交作者邮箱用 noreply 并推送到远程~~ — 已核实为 `LucasYanzy@users.noreply.github.com`，本地与 `origin/main` 一致
3. ~~设置 description / topics / labels~~ — description 已设、10 个 topics 已设、标签已建
4. ~~开 6 个初始 Issue~~ — 已开，其中 5 个 `good first issue`

**仍需你明确确认才能做：**
5. **按本文件发布 Show HN / Reddit / X / 中文帖** —— 一次都没发过
6. 发布前先完成 Reddit 两版官方 rules 的人工核对（本环境 403 取不到）
7. 是否允许把本文件的修订提交推送到远程

确认其中任何一项后我才执行；不确认就保持现状。
