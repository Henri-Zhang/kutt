const { addMilliseconds } = require("date-fns");
const { body, param, query: queryValidator } = require("express-validator");
const promisify = require("node:util").promisify;
const bcrypt = require("bcryptjs");
const dns = require("node:dns");
const URL = require("node:url");
const ms = require("ms");

const { ROLES } = require("../consts");
const query = require("../queries");
const utils = require("../utils");
const knex = require("../knex");
const env = require("../env");

const dnsLookup = promisify(dns.lookup);

const checkUser = (value, { req }) => !!req.user;
const sanitizeCheckbox = value => value === true || value === "on" || value;

const createLink = [
  body("target")
    .exists({ checkNull: true, checkFalsy: true })
    .withMessage("目标链接不能为空。")
    .isString()
    .trim()
    .isLength({ min: 1, max: 2040 })
    .withMessage("URL 最大长度为 2040。")
    .customSanitizer(utils.addProtocol)
    .custom(value => utils.urlRegex.test(value) || /^(?!https?|ftp)(\w+:|\/\/)/.test(value))
    .withMessage("URL 格式无效。")
    .custom(value => utils.removeWww(URL.parse(value).host) !== env.DEFAULT_DOMAIN)
    .withMessage(`${env.DEFAULT_DOMAIN} 链接不允许。`),
  body("password")
    .optional({ nullable: true, checkFalsy: true })
    .custom(checkUser)
    .withMessage("仅注册用户可使用此字段。")
    .isString()
    .isLength({ min: 3, max: 64 })
    .withMessage("密码长度须在 3 到 64 之间。"),
  body("customurl")
    .optional({ nullable: true, checkFalsy: true })
    .custom(checkUser)
    .withMessage("仅注册用户可使用此字段。")
    .isString()
    .trim()
    .isLength({ min: 1, max: 64 })
    .withMessage("自定义 URL 长度须在 1 到 64 之间。")
    .custom(value => utils.customAddressRegex.test(value) || utils.customAlphabetRegex.test(value))
    .withMessage("自定义 URL 格式无效。")
    .custom(value => !utils.preservedURLs.some(url => url.toLowerCase() === value))
    .withMessage("不能使用此自定义 URL。"),
  body("reuse")
    .optional({ nullable: true })
    .custom(checkUser)
    .withMessage("仅注册用户可使用此字段。")
    .isBoolean()
    .withMessage("Reuse 必须为布尔值。"),
  body("description")
    .optional({ nullable: true, checkFalsy: true })
    .isString()
    .trim()
    .isLength({ min: 1, max: 2040 })
    .withMessage("描述长度须在 1 到 2040 之间。"),
  body("expire_in")
    .optional({ nullable: true, checkFalsy: true })
    .isString()
    .trim()
    .custom(value => {
      try {
        return !!ms(value);
      } catch {
        return false;
      }
    })
    .withMessage("过期时间格式无效。有效示例：1m, 8h, 42 days。")
    .customSanitizer(ms)
    .custom(value => value >= ms("1m"))
    .withMessage("过期时间须大于 1 分钟。")
    .customSanitizer(value => utils.dateToUTC(addMilliseconds(new Date(), value))),
  body("domain")
    .optional({ nullable: true, checkFalsy: true })
    .customSanitizer(value => value === env.DEFAULT_DOMAIN ? null : value)
    .custom(checkUser)
    .withMessage("仅注册用户可使用此字段。")
    .isString()
    .withMessage("域名应为字符串。")
    .customSanitizer(value => value.toLowerCase())
    .custom(async (address, { req }) => {
      const domain = await query.domain.find({
        address,
        user_id: req.user.id
      });
      req.body.fetched_domain = domain || null;

      if (!domain) return Promise.reject();
    })
    .withMessage("不能使用此域名。")
];

const editLink = [
  body("target")
    .optional({ checkFalsy: true, nullable: true })
    .isString()
    .trim()
    .isLength({ min: 1, max: 2040 })
    .withMessage("URL 最大长度为 2040。")
    .customSanitizer(utils.addProtocol)
    .custom(value => utils.urlRegex.test(value) || /^(?!https?|ftp)(\w+:|\/\/)/.test(value))
    .withMessage("URL 格式无效。")
    .custom(value => utils.removeWww(URL.parse(value).host) !== env.DEFAULT_DOMAIN)
    .withMessage(`${env.DEFAULT_DOMAIN} 链接不允许。`),
  body("password")
    .optional({ nullable: true, checkFalsy: true })
    .isString()
    .isLength({ min: 3, max: 64 })
    .withMessage("密码长度须在 3 到 64 之间。"),
  body("address")
    .optional({ checkFalsy: true, nullable: true })
    .isString()
    .trim()
    .isLength({ min: 1, max: 64 })
    .withMessage("自定义 URL 长度须在 1 到 64 之间。")
    .custom(value => utils.customAddressRegex.test(value) || utils.customAlphabetRegex.test(value))
    .withMessage("自定义 URL 格式无效。")
    .custom(value => !utils.preservedURLs.some(url => url.toLowerCase() === value))
    .withMessage("不能使用此自定义 URL。"),
  body("expire_in")
    .optional({ nullable: true, checkFalsy: true })
    .isString()
    .trim()
    .custom(value => {
      try {
        return !!ms(value);
      } catch {
        return false;
      }
    })
    .withMessage("过期时间格式无效。有效示例：1m, 8h, 42 days。")
    .customSanitizer(ms)
    .custom(value => value >= ms("1m"))
    .withMessage("过期时间须大于 1 分钟。")
    .customSanitizer(value => utils.dateToUTC(addMilliseconds(new Date(), value))),
  body("description")
    .optional({ nullable: true, checkFalsy: true })
    .isString()
    .trim()
    .isLength({ min: 0, max: 2040 })
    .withMessage("描述长度须在 0 到 2040 之间。"),
  param("id", "ID 无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 36, max: 36 })
];

const redirectProtected = [
  body("password", "密码无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isString()
    .isLength({ min: 3, max: 64 })
    .withMessage("密码长度须在 3 到 64 之间。"),
  param("id", "ID 无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 36, max: 36 })
];

const addDomain = [
  body("address", "域名无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 3, max: 64 })
    .withMessage("域名长度须在 3 到 64 之间。")
    .trim()
    .customSanitizer(utils.addProtocol)
    .custom(value => utils.urlRegex.test(value))
    .customSanitizer(value => {
      const parsed = URL.parse(value);
      return utils.removeWww(parsed.hostname || parsed.href);
    })
    .custom(value => value !== env.DEFAULT_DOMAIN)
    .withMessage("不能使用默认域名。")
    .custom(async value => {
      const domain = await query.domain.find({ address: value });
      if (domain?.user_id || domain?.banned) return Promise.reject();
    })
    .withMessage("不能添加此域名。"),
  body("homepage")
    .optional({ checkFalsy: true, nullable: true })
    .customSanitizer(utils.addProtocol)
    .custom(value => utils.urlRegex.test(value) || /^(?!https?|ftp)(\w+:|\/\/)/.test(value))
    .withMessage("主页 URL 无效。")
];

const addDomainAdmin = [
  body("address", "域名无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 3, max: 64 })
    .withMessage("域名长度须在 3 到 64 之间。")
    .trim()
    .customSanitizer(utils.addProtocol)
    .custom(value => utils.urlRegex.test(value))
    .customSanitizer(value => {
      const parsed = URL.parse(value);
      return utils.removeWww(parsed.hostname || parsed.href);
    })
    .custom(value => value !== env.DEFAULT_DOMAIN)
    .withMessage("不能添加默认域名。")
    .custom(async value => {
      const domain = await query.domain.find({ address: value });
      if (domain) return Promise.reject();
    })
    .withMessage("域名已存在。"),
  body("homepage")
    .optional({ checkFalsy: true, nullable: true })
    .customSanitizer(utils.addProtocol)
    .custom(value => utils.urlRegex.test(value) || /^(?!https?|ftp)(\w+:|\/\/)/.test(value))
    .withMessage("主页 URL 无效。"),
  body("banned")
    .optional({ nullable: true })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean(),
]

const removeDomain = [
  param("id", "ID 无效。")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isLength({ min: 36, max: 36 })
];

const removeDomainAdmin = [
  param("id", "ID 无效。")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isNumeric(),
  queryValidator("links")
    .optional({ nullable: true })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean(),
];

const deleteLink = [
  param("id", "ID 无效。")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isLength({ min: 36, max: 36 })
];

const reportLink = [
  body("link", "未提供链接。")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .customSanitizer(utils.addProtocol)
    .custom(
      value => utils.removeWww(URL.parse(value).host) === env.DEFAULT_DOMAIN
    )
    .withMessage(`只能举报 ${env.DEFAULT_DOMAIN} 链接。`)
];

const banLink = [
  param("id", "ID 无效。")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isLength({ min: 36, max: 36 }),
  body("host", '"host" 应为布尔值。')
    .optional({
      nullable: true
    })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean(),
  body("user", '"user" 应为布尔值。')
    .optional({
      nullable: true
    })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean(),
  body("userLinks", '"userLinks" 应为布尔值。')
    .optional({
      nullable: true
    })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean(),
  body("domain", '"domain" 应为布尔值。')
    .optional({
      nullable: true
    })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean()
];

const banUser = [
  param("id", "ID 无效。")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isNumeric(),
  body("links", '"links" 应为布尔值。')
    .optional({
      nullable: true
    })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean(),
  body("domains", '"domains" 应为布尔值。')
    .optional({
      nullable: true
    })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean()
];

const banDomain = [
  param("id", "ID 无效。")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isNumeric(),
  body("links", '"links" 应为布尔值。')
    .optional({
      nullable: true
    })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean(),
  body("domains", '"domains" 应为布尔值。')
    .optional({
      nullable: true
    })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean()
];

const createUser = [
  body("password", "密码无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("密码长度须在 8 到 64 之间。"),
  body("email", "Email 无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage("Email 长度不能超过 255。")
    .isEmail()
    .custom(async (value, { req }) => {
      const user = await query.user.find({ email: value });
      if (user) 
        return Promise.reject();
    })
    .withMessage("用户已存在。"),
  body("role", "角色无效。")
    .optional({ nullable: true, checkFalsy: true })
    .trim()
    .isIn([ROLES.USER, ROLES.ADMIN]),
  body("verified")
    .optional({ nullable: true })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean(),
  body("banned")
    .optional({ nullable: true })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean(),
  body("verification_email")
    .optional({ nullable: true })
    .customSanitizer(sanitizeCheckbox)
    .isBoolean(),
];

const getStats = [
  param("id", "ID 无效。")
    .exists({
      checkFalsy: true,
      checkNull: true
    })
    .isLength({ min: 36, max: 36 })
];

const signup = [
  body("password", "密码无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("密码长度须在 8 到 64 之间。"),
  body("email", "Email 无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .trim()
    .isLength({ min: 0, max: 255 })
    .withMessage("Email 长度不能超过 255。")
    .isEmail()
];

const signupEmailTaken = [
  body("email", "Email 无效。")
    .custom(async (value, { req }) => {
      const user = await query.user.find({ email: value });

      if (user) {
        req.user = user;
      }

      if (user?.verified) {
        return Promise.reject();
      }
    })
    .withMessage("不能使用此邮箱地址。")
];

const login = [
  body("password", "密码无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("密码长度须在 8 到 64 之间。"),
  body("email", "Email 无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage("Email 长度不能超过 255。")
    .isEmail()
];

const createAdmin = [
  body("password", "密码无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("密码长度须在 8 到 64 之间。"),
  body("email", "Email 无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .trim()
    .isLength({ min: 0, max: 255 })
    .withMessage("Email 长度不能超过 255。")
    .isEmail()
];

const changePassword = [
  body("currentpassword", "密码无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("密码长度须在 8 到 64 之间。"),
  body("newpassword", "密码无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("密码长度须在 8 到 64 之间。")
];

const changeEmail = [
  body("password", "密码无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("密码长度须在 8 到 64 之间。"),
  body("email", "Email 地址无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage("Email 长度不能超过 255。")
    .isEmail()
];

const resetPassword = [
  body("email", "Email 无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .trim()
    .isLength({ min: 0, max: 255 })
    .withMessage("Email 长度不能超过 255。")
    .isEmail()
];

const newPassword = [
  body("reset_password_token", "重置密码令牌无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 36, max: 36 }),
  body("new_password", "密码无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .withMessage("密码长度须在 8 到 64 之间。"),
  body("repeat_password", "密码无效。")
    .custom((repeat_password, { req }) => {
      return repeat_password === req.body.new_password;
    })
    .withMessage("两次输入的密码不一致。"),
];

const deleteUser = [
  body("password", "密码无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isLength({ min: 8, max: 64 })
    .custom(async (password, { req }) => {
      const isMatch = await bcrypt.compare(password, req.user.password);
      if (!isMatch) return Promise.reject();
    })
    .withMessage("密码不正确。")
];

const deleteUserByAdmin = [
  param("id", "ID 无效。")
    .exists({ checkFalsy: true, checkNull: true })
    .isNumeric()
];

async function bannedDomain(domain) {
  const isBanned = await query.domain.find({
    address: domain,
    banned: true
  });

  if (isBanned) {
    throw new utils.CustomError("域名已被封禁。", 400);
  }
};

async function bannedHost(domain) {
  let isBanned;

  try {
    const dnsRes = await dnsLookup(domain);

    if (!dnsRes || !dnsRes.address) return;

    isBanned = await query.host.find({
      address: dnsRes.address,
      banned: true
    });
  } catch (error) {
    isBanned = null;
  }

  if (isBanned) {
    throw new utils.CustomError("URL 包含恶意/诈骗内容。", 400);
  }
};

module.exports = {
  addDomain,
  addDomainAdmin,
  banDomain,
  banLink,
  banUser,
  bannedDomain,
  bannedHost,
  changeEmail,
  changePassword,
  checkUser,
  createAdmin,
  createLink,
  createUser,
  deleteLink,
  deleteUser,
  deleteUserByAdmin,
  editLink,
  getStats,
  login, 
  newPassword,
  redirectProtected,
  removeDomain,
  removeDomainAdmin,
  reportLink,
  resetPassword,
  signup,
  signupEmailTaken,
}
