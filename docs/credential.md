# Qoder2api 凭据

- 登录：浏览器授权（device flow，PKCE S256 + challenge，900 秒窗口），
  授权页 `https://qoder.cn/device/selectAccounts?...`。
- 凭据落盘：`<状态目录>/credentials.json`（persist:true）。
- 启动时自动签到检查（[benefit] 签到检查）。
