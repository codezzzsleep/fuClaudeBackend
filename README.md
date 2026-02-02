# fuClaudeBackend

中文文档 | English: `README_EN.md`

## 简介
这是基于开源 fuclaude 的轻量后端代理 + Key 管理后台。项目主要为「始皇」相关使用场景做的管理增强版本，并参考了社区相关讨论的思路。

## 功能
- 访客/站点登录
- 管理后台：用户与 Key 管理
- 选择账号页面（带状态展示）
- Key 过期时间支持（过期 Key 不展示）

## 快速开始
1) 复制 `config.example.json` 为 `config.json`
2) (可选) 复制 `data.example.json` 为 `data.json`（或首次保存时自动生成）
3) 运行 `node sever.js`
4) 打开 `http://localhost:3000`

## 配置说明（config.json）
- `ORIGINAL_WEBSITE`: 上游站点地址，建议自己部署
- `SESSION_KEYS`: `{ id, label, value, expiresAt }` 列表
- `DEFAULT_KEY_ID`: 默认 Key ID
- `SESSION_KEY`: 旧版单 Key（可留空）
- `SITE_PASSWORD` / `GUEST_PASSWORD`: 登录密码
- `PORT`: 端口

## 数据文件（data.json）
- `keys`: 与 `SESSION_KEYS` 结构一致（`value` 为私密）
- `defaultKeyId`
- `users`: `{ username, active, isolated, keys, createdAt, lastLoginAt, expiresAt }`

## Key 过期时间
- `expiresAt` 支持任意 `Date.parse()` 可解析的字符串（推荐 ISO 8601）
- 管理后台可手动输入
- 为空时默认写入后 27 天
- 过期 Key 不会在 `/choose` 中展示


## 参考与致谢
- fuclaude 原项目：https://github.com/wozulong/fuclaude
- 社区讨论：https://linux.do/t/topic/131611
- 思路参考：https://linux.do/t/topic/131757
- 社区用户：https://linux.do/u/neo
