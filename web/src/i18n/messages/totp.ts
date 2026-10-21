import { defineMessages } from "@/i18n/define"

// Strings shared by every place that handles a second factor: the sign-in
// challenge, enrolment and the account security card.
export const totp = defineMessages({
  en: {
    code: "Verification code",
    recoveryCode: "Recovery code",
    useRecovery: "Use a recovery code",
    useApp: "Use your authenticator app",
    codeInvalid: "Enter the 6-digit code",
    recoveryInvalid: "Enter a recovery code like abcde-fghij",
    enrol: {
      scan: "Scan this QR code with an authenticator app.",
      qrLabel: "QR code for your authenticator app",
      manual: "Can't scan it? Enter this setup key instead:",
      secret: "Setup key",
      code: "Code from the app",
      codeHint: "Enter the 6-digit code the app now shows.",
    },
    recovery: {
      title: "Save your recovery codes",
      description:
        "If you lose your authenticator app, sign in with one of these codes. Each code works once, and they will not be shown again.",
      copy: "Copy codes",
      download: "Download",
      saved: "I have saved these codes somewhere safe",
      fileHeader: "Fire ID recovery codes for {username}",
      fileNote: "Each code works once. Generated {date}.",
    },
  },
  zh: {
    code: "验证码",
    recoveryCode: "恢复码",
    useRecovery: "使用恢复码",
    useApp: "使用身份验证器应用",
    codeInvalid: "请输入 6 位验证码",
    recoveryInvalid: "请输入恢复码，格式如 abcde-fghij",
    enrol: {
      scan: "用身份验证器应用扫描此二维码。",
      qrLabel: "身份验证器应用的二维码",
      manual: "无法扫描？请手动输入以下密钥：",
      secret: "设置密钥",
      code: "应用中的验证码",
      codeHint: "输入应用当前显示的 6 位验证码。",
    },
    recovery: {
      title: "保存恢复码",
      description:
        "如果丢失了身份验证器应用，可以用这些恢复码登录。每个恢复码只能使用一次，且只显示这一次。",
      copy: "复制恢复码",
      download: "下载",
      saved: "我已将这些恢复码保存在安全的地方",
      fileHeader: "{username} 的 Fire ID 恢复码",
      fileNote: "每个恢复码只能使用一次。生成于 {date}。",
    },
  },
})
