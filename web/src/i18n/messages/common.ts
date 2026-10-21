import { defineMessages } from "@/i18n/define"

export const common = defineMessages({
  en: {
    appName: "Fire ID",
    actions: {
      continue: "Continue",
      cancel: "Cancel",
      back: "Back",
      close: "Close",
      copy: "Copy",
      copied: "Copied",
      retry: "Retry",
    },
    states: {
      never: "Never",
    },
    errors: {
      title: "Something went wrong",
      loadFailed: "Could not load this page",
      network: "Cannot reach Fire ID. Check your connection and try again.",
      rateLimitedNoWait: "Too many attempts. Try again later.",
      // Keyed by the API error code (docs/api.md).
      invalid_credentials: "Incorrect username or password.",
      invalid_code: "That code is wrong or has expired.",
      rate_limited: "Too many attempts. Try again in {seconds} seconds.",
      cross_site:
        "The request was refused because it came from another site. Open Fire ID directly and try again.",
      email_unavailable: "Email sign-in is not available on this server.",
      invalid_body:
        "The server did not understand the request. Reload the page and try again.",
      internal_error:
        "Something went wrong on the server. Try again in a moment.",
      unauthenticated: "Your session has ended. Sign in again.",
      invalid_token:
        "The setup token is not valid. Copy it again from the server log.",
      setup_unavailable: "Fire ID has already been set up.",
      weak_password: "That password is too weak. Choose a longer one.",
      conflict: "That username or email is already in use.",
      totp_enabled: "Two-step verification is already on.",
      totp_not_enabled: "Two-step verification is off.",
      totp_not_pending: "This setup has expired. Start again.",
      forbidden: "You are not allowed to do this.",
      second_factor_not_required:
        "Two-step verification was turned off for this account. Sign in again.",
      totp_enrol_required:
        "This account must set up two-step verification first. Sign in with your password to do that.",
    },
    copyFailed: "Could not copy to the clipboard",
  },
  zh: {
    appName: "Fire ID",
    actions: {
      continue: "继续",
      cancel: "取消",
      back: "返回",
      close: "关闭",
      copy: "复制",
      copied: "已复制",
      retry: "重试",
    },
    states: {
      never: "从未",
    },
    errors: {
      title: "出错了",
      loadFailed: "页面加载失败",
      network: "无法连接 Fire ID，请检查网络后重试。",
      rateLimitedNoWait: "尝试次数过多，请稍后再试。",
      invalid_credentials: "用户名或密码错误。",
      invalid_code: "验证码错误或已过期。",
      rate_limited: "尝试次数过多，请在 {seconds} 秒后重试。",
      cross_site: "请求来自其他网站，已被拒绝。请直接打开 Fire ID 后重试。",
      email_unavailable: "此服务器未开启邮件登录。",
      invalid_body: "服务器无法识别该请求，请刷新页面后重试。",
      internal_error: "服务器出错了，请稍后重试。",
      unauthenticated: "登录已失效，请重新登录。",
      invalid_token: "初始化令牌无效，请从服务端日志中重新复制。",
      setup_unavailable: "Fire ID 已完成初始化。",
      weak_password: "密码强度不够，请换一个更长的密码。",
      conflict: "该用户名或邮箱已被使用。",
      totp_enabled: "两步验证已开启。",
      totp_not_enabled: "两步验证未开启。",
      totp_not_pending: "本次设置已过期，请重新开始。",
      forbidden: "你没有权限执行此操作。",
      second_factor_not_required: "此账户的两步验证已关闭，请重新登录。",
      totp_enrol_required: "此账户需要先设置两步验证，请使用密码登录完成设置。",
    },
    copyFailed: "无法复制到剪贴板",
  },
})

export const shell = defineMessages({
  en: {
    language: "Language",
    notifications: "Notifications",
    theme: {
      label: "Theme",
      light: "Light",
      dark: "Dark",
      system: "System",
    },
    user: {
      menu: "Account menu",
      signOut: "Sign out",
      signedOut: "Signed out",
    },
    sessionExpired: "Your session has expired. Sign in again.",
    chunkError: "A new version of Fire ID is available. Reload to continue.",
    reload: "Reload",
    notFound: {
      title: "Page not found",
      description: "The page you are looking for does not exist.",
      home: "Go to your account",
    },
  },
  zh: {
    language: "语言",
    notifications: "通知",
    theme: {
      label: "主题",
      light: "浅色",
      dark: "深色",
      system: "跟随系统",
    },
    user: {
      menu: "账户菜单",
      signOut: "退出登录",
      signedOut: "已退出登录",
    },
    sessionExpired: "登录已过期，请重新登录。",
    chunkError: "Fire ID 已更新，请刷新页面继续。",
    reload: "刷新",
    notFound: {
      title: "页面不存在",
      description: "你访问的页面不存在。",
      home: "前往我的账户",
    },
  },
})
