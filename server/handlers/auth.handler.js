const { differenceInDays, addMinutes } = require("date-fns");
const { nanoid } = require("nanoid");
const passport = require("passport");
const { randomUUID } = require("node:crypto");
const bcrypt = require("bcryptjs");

const { ROLES } = require("../consts");
const query = require("../queries");
const utils = require("../utils");
const redis = require("../redis");
const mail = require("../mail");
const env = require("../env");

const CustomError = utils.CustomError;

function authenticate(type, error, isStrict, redirect) {
  return function auth(req, res, next) {
    if (req.user) return next();

    passport.authenticate(type, (err, user, info) => {
      if (
        (err || info instanceof Error) &&
        type === "oidc"
      ) {
        return next(new CustomError("OIDC 认证失败。", 401));
      };

      if (err) return next(err);

      if (
        req.isHTML &&
        redirect &&
        ((!user && isStrict) ||
        (user && isStrict && !user.verified) ||
        (user && user.banned))
      ) {
        if (redirect === "page") {
          res.redirect("/logout");
          return;
        }
        if (redirect === "header") {
          res.setHeader("HX-Redirect", "/logout");
          res.send("NOT_AUTHENTICATED");
          return;
        }
      }
      
      if (!user && isStrict) {
        throw new CustomError(error, 401);
      }

      if (user && user.banned) {
        throw new CustomError("你已被禁止使用本站。", 403);
      }

      if (user && isStrict && !user.verified) {
        throw new CustomError("你的邮箱地址尚未验证。请重新注册以获取验证链接。", 400);
      }

      if (user) {
        res.locals.isAdmin = utils.isAdmin(user);
        req.user = {
          ...user,
          admin: utils.isAdmin(user)
        };

        // renew token if it's been at least one day since the token has been created
        // only do it for html page requests not api requests
        if (info?.exp && req.isHTML && redirect === "page") {
          const diff = Math.abs(differenceInDays(new Date(info.exp * 1000), new Date()));
          if (diff < 6) {
            const token = utils.signToken(user);
            utils.deleteCurrentToken(res);
            utils.setToken(res, token);
          }
        }
      }
      return next();
    })(req, res, next);
  }
}

const local = authenticate("local", "登录凭据错误。", true, null);
const jwt = authenticate("jwt", "未授权。", true, "header");
const jwtPage = authenticate("jwt", "未授权。", true, "page");
const jwtLoose = authenticate("jwt", "未授权。", false, "header");
const jwtLoosePage = authenticate("jwt", "未授权。", false, "page");
const apikey = authenticate("localapikey", "API 密钥不正确。", false, null);
const oidc = authenticate("oidc", "未授权", true, "page");

function admin(req, res, next) {
  if (req.user.admin) return next();
  throw new CustomError("未授权", 401);
}

async function signup(req, res) {
  const salt = await bcrypt.genSalt(12);
  const password = await bcrypt.hash(req.body.password, salt);
  
  const user = await query.user.add(
    { email: req.body.email, password },
    req.user
  );
  
  await mail.verification(user);

  if (req.isHTML) {
    res.render("partials/auth/verify");
    return;
  }
  
  return res.status(201).send({ message: "验证邮件已发送。" });
}

async function createAdminUser(req, res) {
  const isThereAUser = await query.user.findAny();
  if (isThereAUser) {
    throw new CustomError("无法创建管理员账号，因为已存在用户。", 400);
  }
  
  const salt = await bcrypt.genSalt(12);
  const password = await bcrypt.hash(req.body.password, salt);

  const user = await query.user.add({
    email: req.body.email, 
    password, 
    role: ROLES.ADMIN, 
    verified: true 
  });

  const token = utils.signToken(user);

  if (req.isHTML) {
    utils.setToken(res, token);
    res.render("partials/auth/welcome");
    return;
  }
  
  return res.status(201).send({ token });
}

function login(req, res) {
  const token = utils.signToken(req.user);

  if (req.isHTML) {
    utils.setToken(res, token);
    res.render("partials/auth/welcome");
    return;
  }
  
  return res.status(200).send({ token });
}

async function verify(req, res, next) {
  if (!req.params.verificationToken) return next();

  const user = await query.user.update(
    {
      verification_token: req.params.verificationToken,
      verification_expires: [">", utils.dateToUTC(new Date())]
    },
    {
      verified: true,
      verification_token: null,
      verification_expires: null
    }
  );
  
  if (user) {
    const token = utils.signToken(user);
    utils.deleteCurrentToken(res);
    utils.setToken(res, token);
    res.locals.token_verified = true;
    req.cookies.token = token;
  }
  
  return next();
}

async function changePassword(req, res) {
  const isMatch = await bcrypt.compare(req.body.currentpassword, req.user.password);
  if (!isMatch) {
    const message = "当前密码不正确。";
    res.locals.errors = { currentpassword: message };
    throw new CustomError(message, 401);
  }

  const salt = await bcrypt.genSalt(12);
  const newpassword = await bcrypt.hash(req.body.newpassword, salt);
  
  const user = await query.user.update({ id: req.user.id }, { password: newpassword });
  
  if (!user) {
    throw new CustomError("无法修改密码，请稍后重试。");
  }

  if (req.isHTML) {
    res.setHeader("HX-Trigger-After-Swap", "resetChangePasswordForm");
    res.render("partials/settings/change_password", {
      success: "密码已修改。"
    });
    return;
  }
  
  return res
    .status(200)
    .send({ message: "密码已成功修改。" });
}

async function generateApiKey(req, res) {
  const apikey = nanoid(40);
  
  if (env.REDIS_ENABLED) {
    redis.remove.user(req.user);
  }
  
  const user = await query.user.update({ id: req.user.id }, { apikey });
  
  if (!user) {
    throw new CustomError("无法生成 API 密钥，请稍后重试。");
  }

  if (req.isHTML) {
    res.render("partials/settings/apikey", {
      user: { apikey },
    });
    return;
  }
  
  return res.status(201).send({ apikey });
}

async function resetPassword(req, res) {
  const user = await query.user.update(
    { email: req.body.email },
    {
      reset_password_token: randomUUID(),
      reset_password_expires: utils.dateToUTC(addMinutes(new Date(), 30))
    }
  );

  if (user) {
    mail.resetPasswordToken(user).catch(error => {
      console.error("Send reset-password token email error:\n", error);
    });
  }

  if (req.isHTML) {
    res.render("partials/reset_password/request_form", {
      message: "如果该邮箱地址存在，重置密码邮件将发送至该邮箱。"
    });
    return;
  }
  
  return res.status(200).send({
    message: "如果邮箱地址存在，重置密码邮件已发送。"
  });
}

async function newPassword(req, res) {
  const { new_password, reset_password_token } = req.body;

  const salt = await bcrypt.genSalt(12);
  const password = await bcrypt.hash(req.body.new_password, salt);
  
  const user = await query.user.update(
    {
      reset_password_token,
      reset_password_expires: [">", utils.dateToUTC(new Date())]
    },
    { 
      reset_password_expires: null, 
      reset_password_token: null,
      password,
    }
  );

  if (!user) {
    throw new CustomError("无法设置密码，请稍后重试。");
  }

  res.render("partials/reset_password/new_password_success");
}

async function changeEmailRequest(req, res) {
  const { email, password } = req.body;
  
  const isMatch = await bcrypt.compare(password, req.user.password);
  
  if (!isMatch) {
    const error = "密码不正确。";
    res.locals.errors = { password: error };
    throw new CustomError(error, 401);
  }
  
  const user = await query.user.find({ email });
  
  if (user) {
    const error = "不能使用此邮箱地址。";
    res.locals.errors = { email: error };
    throw new CustomError(error, 400);
  }
  
  const updatedUser = await query.user.update(
    { id: req.user.id },
    {
      change_email_address: email,
      change_email_token: randomUUID(),
      change_email_expires: utils.dateToUTC(addMinutes(new Date(), 30))
    }
  );
  
  if (updatedUser) {
    await mail.changeEmail({ ...updatedUser, email });
  }

  const message = "验证链接已发送到请求的邮箱地址。"
  
  if (req.isHTML) {
    res.setHeader("HX-Trigger-After-Swap", "resetChangeEmailForm");
    res.render("partials/settings/change_email", {
      success: message
    });
    return;
  }
  
  return res.status(200).send({ message });
}

async function changeEmail(req, res, next) {
  const changeEmailToken = req.params.changeEmailToken;
  
  if (changeEmailToken) {
    const foundUser = await query.user.find({
      change_email_token: changeEmailToken,
      change_email_expires: [">", utils.dateToUTC(new Date())]
    });
  
    if (!foundUser) return next();
  
    const user = await query.user.update(
      { id: foundUser.id },
      {
        change_email_token: null,
        change_email_expires: null,
        change_email_address: null,
        email: foundUser.change_email_address
      }
    );
  
    if (user) {
      const token = utils.signToken(user);
      utils.deleteCurrentToken(res);
      utils.setToken(res, token);
      res.locals.token_verified = true;
      req.cookies.token = token;
    }
  }
  return next();
}

function featureAccess(features, redirect) {
  return function(req, res, next) {
    for (let i = 0; i < features.length; ++i) {
      if (!features[i]) {
        if (redirect) {
          return res.redirect("/");
        } else {
          throw new CustomError("请求不被允许。", 400);
        }
      } 
    }
    next();
  }
}

function featureAccessPage(features) {
  return featureAccess(features, true);
}

module.exports = {
  admin,
  apikey,
  changeEmail,
  changeEmailRequest,
  changePassword,
  createAdminUser,
  featureAccess,
  featureAccessPage,
  generateApiKey,
  jwt,
  jwtLoose,
  jwtLoosePage,
  jwtPage,
  local,
  login,
  newPassword,
  oidc,
  resetPassword,
  signup,
  verify,
}
