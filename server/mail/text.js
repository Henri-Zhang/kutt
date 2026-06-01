module.exports.verifyMailText = `你正在尝试修改你在 {{site_name}} 上的邮箱地址。

请使用以下链接验证你的邮箱地址。

https://{{domain}}/verify/{{verification}}`;

module.exports.changeEmailText = `感谢你在 {{site_name}} 上创建账号。

请使用以下链接验证你的邮箱地址。

https://{{domain}}/verify-email/{{verification}}`;

module.exports.resetMailText = `你的账号收到了重置密码的请求。

请点击以下链接重置密码。如果你没有发起此请求，无需采取任何操作。

https://{{domain}}/reset-password/{{resetpassword}}`;
