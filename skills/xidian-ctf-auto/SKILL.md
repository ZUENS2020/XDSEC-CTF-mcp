---
name: xidian-ctf-auto
description: 使用 Playwright 无头浏览器自动化西电 CTF 平台（ctf.xidian.edu.cn）：题目抓取、附件下载、在线环境管理、flag 提交。
allowed-tools: functions.exec_command, mcp__computer_use__.*, tool_search.tool_search_tool
---

# XDCTF Auto (Playwright Only)

## 输入约定
工作目录 `setting.md` 提供认证信息，支持以下键名（任一别名即可）：

- 账号：`xdctf_account` / `account` / `username`
- 密码：`xdctf_password` / `password`
- 可选 token：`xdctf_token`
- 可选验证码答案：`captcha_answer` / `xdctf_captcha_answer`（`pow` 验证默认自动求解，通常不需要填）

示例：

```md
xdctf_account: your_account
xdctf_password: your_password
```

> 如果 `setting.md` 里直接给了 `xdctf_token`，脚本优先用 token，不走登录。

## 脚本路径
- [xdctf_automation.mjs](/Users/zuens2020/Documents/XDSEC-CTF-mcp/skills/xidian-ctf-auto/scripts/xdctf_automation.mjs)

## 依赖
```bash
npm i -g playwright
npx playwright install chromium
```

## 常用命令
```bash
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs auth login --setting-file setting.md
```

```bash
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs init challenge --game-id 25 --challenge-id 123 --dest ./downloads
```

```bash
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs games list --page 1 --page-size 20
```

```bash
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs challenges list --game-id 25
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs challenges description --game-id 25 --challenge-id 123
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs challenges hints --game-id 25 --challenge-id 123
```

```bash
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs files list --game-id 25 --challenge-id 123
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs files download --game-id 25 --challenge-id 123 --all-files --dest ./downloads
```

```bash
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs instance env --game-id 25 --challenge-id 123
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs instance start --game-id 25 --challenge-id 123
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs instance status --game-id 25 --challenge-id 123
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs instance extend --game-id 25 --challenge-id 123
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs instance endpoint --game-id 25 --challenge-id 123
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs instance renew --game-id 25 --challenge-id 123
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs instance shutdown --game-id 25 --challenge-id 123
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs instance stop --game-id 25 --challenge-id 123
```

```bash
node skills/xidian-ctf-auto/scripts/xdctf_automation.mjs submit flag --game-id 25 --challenge-id 123 --flag 'flag{...}' --check-after
```

## 工作流建议
1. `auth login` 确保 token 可用。
2. `games list` / `challenges list` 定位题目。
3. `files list` + `files download` 拉附件。
4. `instance start` 启环境。
5. `submit flag` 交 flag 并回查。
