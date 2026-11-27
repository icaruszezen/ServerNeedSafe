import type { HostMemory, ServerView } from '../types';

export const MASK_PLACEHOLDER = '***';
export const DEFAULT_MASK_SENTINEL = '\uE000SNS_MASK\uE001';

export interface SensitiveMaskContext {
  servers?: Pick<ServerView, 'host' | 'port' | 'username' | 'default_path'>[];
  hostMemories?: Pick<HostMemory, 'deploy_paths'>[];
}

export interface SensitiveMasker {
  maskText: (raw: string) => string;
  maskMarkdownWithSentinel: (raw: string) => { masked: string; sentinel: string };
  maskPortsNote: (raw: string) => string;
  maskDeployPath: (raw: string) => string;
  maskServiceName: (raw: string) => string;
  maskServerName: (raw: string) => string;
}

const RE_PEM_BLOCK =
  /-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|PUBLIC KEY|CERTIFICATE|RSA|EC|DSA|OPENSSH|PGP)[A-Z0-9 ]*-----[\s\S]*?-----END [A-Z0-9 ]*(?:PRIVATE KEY|PUBLIC KEY|CERTIFICATE|RSA|EC|DSA|OPENSSH|PGP)[A-Z0-9 ]*-----/g;

const RE_URI =
  /\b(?:https?|wss?|ssh|sftp|ftps?|file|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|ldaps?|socks5?h?|vmess|vless|trojan|ssr?|hysteria2?|tuic|jdbc:[a-z0-9]+):\/\/[^\s'"`<>，。；、（）【】《》]+/gi;

const RE_SSH_PUBKEY =
  /\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[ \t]+[A-Za-z0-9+/=]{16,}(?:[ \t]+[^\s,;'")\]`]+)?/g;

const RE_SSH_FINGERPRINT =
  /\b(?:SHA256:[A-Za-z0-9+/=]{20,}|MD5:(?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2})\b/g;

const RE_AUTH_HEADER_VALUE = /\b(?:Bearer|Basic)[ \t]+[A-Za-z0-9._\-+/=]{8,}/gi;

const RE_JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/g;

const RE_WELL_KNOWN_TOKENS =
  /\b(?:sk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_\-]{12,}|sns_mcp_[A-Za-z0-9_\-]{10,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|glpat-[A-Za-z0-9_\-]{16,}|A(?:KIA|SIA)[0-9A-Z]{16}|LTAI[A-Za-z0-9]{12,}|AKID[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|(?:pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,})\b/g;

const RE_CLOUD_ARN =
  /\b(?:arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d*:[A-Za-z0-9_/:.-]+|acs:[a-z0-9-]+:[a-z0-9-]*:\d*:[A-Za-z0-9_/:.-]+)\b/gi;

const RE_CLOUD_RESOURCE_ID =
  /\b(?:i|ins|ecs|vpc|vsw|sg|eni|vol|snap|eip|alb|nlb|rds|rm)-(?=[a-z0-9]*\d)[a-z0-9]{8,}\b/g;

const RE_UUID =
  /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;

const RE_LONG_HEX =
  /\b(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{32,128}\b/g;

const RE_CLI_AUTH_HEADER = /(-H[ \t]+['"]?Authorization:[ \t]*)[^'"\n]+/gi;
const RE_CLI_SECRET_FLAG =
  /((?:--password|--passwd|--passphrase|--token|--secret|--api-key|--apikey|--auth|--access-token)(?:=|[ \t]+))(?:"[^"\n]*"|'[^'\n]*'|[^\s'"`;]+)/gi;
const RE_CLI_MYSQL_PASS = /(\bmysql(?:dump)?\b[^\n;|&]*?[ \t]-p)([^\s'"`;]+)/gi;
const RE_CLI_REDIS_PASS = /(\bredis-cli\b[^\n;|&]*?[ \t]-a[ \t]+)([^\s'"`;]+)/gi;
const RE_CLI_CURL_USER =
  /(\bcurl\b[^\n;|&]*?[ \t](?:-u|--user)[ \t]+)(?:"[^"\n]*"|'[^'\n]*'|[^\s'"`;]+)/gi;

const RE_KV_EN =
  /(\*\*)?(?<![A-Za-z0-9_])(?:password|passwd|pwd|passphrase|secret(?:_?key)?|api_?key|api[ \t]+key|access_?key(?:_?id)?|access_?token|auth_?token|refresh_?token|private_?key|private[ \t]+key|client_?secret|app_?secret|signing_?key|master_?key|encryption_?key|sns_master_key|webhook_?secret|webhook_?url|db_?pass(?:word)?|mysql_?pwd|pgpassword|redis_?pass(?:word)?|token|credential|authorization|x-api-key|cookie|session_?id|dsn|connection_?string)(\*\*)?[ \t]*([:=：])[ \t]*(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[^\s,;，。；！？）】》'"]+)/gi;

const RE_ENV_SECRET_KV =
  /\b[A-Za-z][A-Za-z0-9_-]{0,40}(?:(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|SIGNING_?KEY|MASTER_?KEY|CREDENTIAL|AUTH_?KEY|WEBHOOK_?URL|DSN)|(?:[_-](?:PASS|PWD)))\b[ \t]*([:=])[ \t]*(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[^\s,;，。；！？）】》'"]+)/gi;

const RE_SSH_CONFIG_DIRECTIVE =
  /(\b(?:HostName|ProxyJump|IdentityFile|BindAddress|ListenAddress)\b[ \t]+)([^\s#;,，。；]+)/gi;

const RE_SERVER_FIELD_ZH =
  /((?:公网|内网|外网|本地|目标|管理|服务器|主机|节点|跳板机|堡垒机|数据库|主库|从库|备库|上游|下游)?(?:IP地址?|主机名|主机地址|域名|部署路径|配置路径|数据目录|日志目录|安装目录|工作目录|文件路径|目录路径|路径)(?:\*\*)?[ \t]*(?:[:=：]|为)[ \t]*)(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[A-Za-z0-9._~@%+\-/:\\*]{2,})/gi;

const RE_KV_ZH_COLON =
  /(\*\*)?(?:登录|管理|管理员|数据库|主库|从库|账号|账户|用户|root|ssh|redis|mysql|postgres|pgsql|mongo|webhook|api|加密|主|访问|授权|签名|认证|验证)?(?:密码|口令|密钥|秘钥|私钥|公钥|令牌|凭据|凭证|鉴权码|授权码|密钥对|连接串|连接字符串|用户名|账号|账户)(\*\*)?[ \t]*([:=：])[ \t]*(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[^\s,;，。；！？）】》'"]+)/gi;

const RE_KV_ZH_IS =
  /(\*\*)?(?:登录|管理|管理员|数据库|主库|从库|账号|账户|用户|root|ssh|redis|mysql|postgres|pgsql|mongo|webhook|api|加密|主|访问|授权|签名|认证|验证)?(?:密码|口令|密钥|秘钥|私钥|公钥|令牌|凭据|凭证|鉴权码|授权码|连接串|连接字符串|用户名|账号|账户)(\*\*)?[ \t]*(为|是)[ \t]*(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[A-Za-z0-9._\-+@#$%^&*!/~]{3,})/gi;

const RE_EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

const RE_SSH_USER_HOST_IP =
  /\b[A-Za-z_][A-Za-z0-9._-]{0,31}@(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?::\d{1,5})?\b/g;

const RE_SSH_CMD_USER_HOST =
  /(\b(?:ssh|scp|sftp|rsync)\b[^\n;|&]*?[ \t]+)([A-Za-z_][A-Za-z0-9._-]{0,31}@[A-Za-z0-9._-]+(?::\d{1,5})?)/gi;

const RE_COMMON_USER_AT_HOST =
  /\b(?:root|admin|administrator|ubuntu|debian|centos|ec2-user|deploy|ops|devops|www-data|postgres|mysql|redis|oracle|git|opc|azureuser)@[A-Za-z0-9][A-Za-z0-9._-]{1,62}(?::\d{1,5})?\b/gi;

const RE_IPV6_BRACKET = /\[(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\](?::\d{1,5})?/g;
const RE_IPV6_FULL =
  /(?<![A-Za-z0-9_:])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:\/\d{1,3})?(?![A-Za-z0-9_:])/g;
const RE_IPV6_COMPRESSED =
  /(?<![A-Za-z0-9_:])(?:(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?|::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6}))(?:\/\d{1,3})?(?![A-Za-z0-9_:])/g;
const RE_IPV6_UNSPEC = /(?<![A-Za-z0-9_:])::(?::\d{1,5}|\/\d{1,3})(?![A-Za-z0-9_:])/g;

const RE_IPV4 =
  /(?<![A-Za-z0-9_.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?:\/(?:3[0-2]|[12]?\d)|:\d{1,5}(?:-\d{1,5})?)?(?![A-Za-z0-9_.])/g;

const RE_IPV4_WILDCARD =
  /(?<![A-Za-z0-9_.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d|\*)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d|\*)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d|\*)(?![A-Za-z0-9_.])/g;

const RE_MAC = /\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b/g;

const RE_DOMAIN =
  /(?<![A-Za-z0-9_@/-])\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com\.cn|net\.cn|org\.cn|gov\.cn|edu\.cn|co\.uk|co\.jp|com\.hk|com\.tw|com\.sg|com|cn|net|org|io|dev|app|cloud|co|me|cc|xyz|top|site|online|tech|ai|gov|edu|mil|uk|de|fr|jp|kr|hk|tw|sg|us|eu|ru|ca|au|nl|ch|internal|local|lan|corp|intranet|home|arpa|cluster|svc)(?::\d{1,5})?\b(?![A-Za-z0-9_-])/gi;

const RE_WIN_PATH =
  /(?:(?<![A-Za-z0-9_])[A-Za-z]:\\|\\\\[A-Za-z0-9._-]+\\)[^\s'"`<>|，。；：、（）【】《》]+/g;

const RE_WIN_SLASH_PATH =
  /(?<![A-Za-z0-9_])[A-Za-z]:\/(?:[^\s'"`<>|，。；：、（）【】《》]+\/)*[^\s'"`<>|，。；：、（）【】《》]+/g;

const RE_HOME_OR_DOT_PATH = /(?<![A-Za-z0-9_.-])(?:~|\.\.?)\/[A-Za-z0-9._~@%+\-/]+\/?/g;

const RE_UNIX_MULTI_PATH =
  /(?<![A-Za-z0-9_./-])\/[A-Za-z0-9._~@%+-]+(?:\/[A-Za-z0-9._~@%+-]+)+\/?/g;

const RE_UNIX_TOP_DIR =
  /(?<![A-Za-z0-9_./-])\/(?:etc|var|opt|srv|home|root|tmp|usr|bin|sbin|lib|lib64|dev|proc|sys|run|mnt|media|boot|data|app|apps|www|web|logs?|backups?|configs?|certs?|ssl|keys?|secrets?|Users|Volumes|Library|Applications|private|docker|k8s|helm)\b\/?/g;

const RE_REL_FILE_PATH =
  /(?<![A-Za-z0-9_./-])[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)+\.(?:conf|cnf|cfg|ini|env|yml|yaml|json|toml|xml|log|sh|bash|zsh|py|rb|pl|php|js|ts|go|sql|db|sqlite|rdb|aof|enc|key|pem|crt|cer|csr|p12|pfx|jks|pub|pid|sock|socket|service|timer|bak|tar|gz|tgz|zip|7z|rar|txt|csv)\b/gi;

const RE_SENSITIVE_FILENAME =
  /\b(?:sshd_config|ssh_config|nginx\.conf|httpd\.conf|apache2\.conf|my\.cnf|mysqld\.cnf|redis\.conf|postgresql\.conf|pg_hba\.conf|mongod\.conf|docker-compose(?:\.[a-z0-9_-]+)?\.ya?ml|authorized_keys|known_hosts|id_rsa(?:\.pub)?|id_ed25519(?:\.pub)?|id_ecdsa(?:\.pub)?|id_dsa(?:\.pub)?|secrets\.enc|vault\.enc|kubeconfig|sudoers|auth\.log|secure\.log|error\.log|access\.log|syslog|messages\.log|shadow|htpasswd|[A-Za-z0-9._-]+\.(?:pem|key|ppk|p12|pfx|jks|ovpn|kdbx))\b/gi;

const RE_DOTENV_FILE =
  /(?<![A-Za-z0-9_.-])\.(?:env(?:\.[A-Za-z0-9_-]+)?|htpasswd|netrc|pgpass|my\.cnf)\b/gi;

const RE_PROTO_PORT = /\b(?:tcp|udp|tcp4|tcp6|udp4|udp6)[/:](\d{1,5}(?:-\d{1,5})?)\b/gi;
const RE_PORT_PROTO = /\b(\d{1,5}(?:-\d{1,5})?)\/(?:tcp|udp|tcp4|tcp6|udp4|udp6)\b/gi;
const RE_BIND_HOST_PORT = /(?<![A-Za-z0-9_])(?:\*|localhost):(\d{1,5}(?:-\d{1,5})?)\b/gi;
const RE_SERVICE_PORT = /(?<![0-9A-Za-z_])([A-Za-z][A-Za-z0-9._-]{1,40}):([1-9]\d{1,4})\b/g;
const RE_STANDALONE_COLON_PORT =
  /(?<=[\s(\['"`，。；：（]|listen[ \t]+|bind[ \t]+):([1-9]\d{1,4})\b/gi;

const RE_CLI_PORT_FLAG =
  /((?:--(?:add-|remove-|listen-)?port|--[ds]port|--publish|-p|-P)(?:=|[ \t]+))(\d{1,5}(?::\d{1,5})?(?:-\d{1,5})?)/g;

const RE_UFW_PORT =
  /(\bufw[ \t]+(?:allow|deny|reject|limit)(?:[ \t]+(?:in|out))?[ \t]+)(\d{1,5}(?:[:\-]\d{1,5})?)\b/gi;

const RE_PORT_PREFIX_LABEL =
  /((?:监听|开放|暴露|放行|绑定|映射|转发|SSH|ssh|管理|服务|业务|内部|外部|公网|内网|默认)?(?:端口号?|ports?|listen|expose|dport|sport)(?:\*\*)?[ \t]*(?:[:=：]|为|是)?[ \t]*)(\d{1,5}(?:-\d{1,5})?(?:[ \t]*(?:[,，、/]|和|与|及)[ \t]*\d{1,5}(?:-\d{1,5})?)*)/gi;

const RE_PORT_SUFFIX_LABEL =
  /(\d{1,5}(?:-\d{1,5})?(?:[ \t]*(?:[,，、/]|和|与|及)[ \t]*\d{1,5}(?:-\d{1,5})?)*)([ \t]*号?端口)/g;

const RE_PORT_VERB_ZH =
  /((?:监听|开放|暴露|放行|映射|转发|绑定)(?:于|在|了|到)?[ \t]*)(\d{2,5}(?:-\d{2,5})?(?:[ \t]*(?:[,，、/]|和|与|及)[ \t]*\d{2,5}(?:-\d{2,5})?)*)(?![ \t]*(?:%|MB|GB|KB|TB|ms|s\b|秒|分钟|小时|天|年|月|日|次|台|条|个|字符))/gi;

const RE_CN_PHONE = /(?<!\d)1[3-9]\d{9}(?!\d)/g;
const RE_CN_ID_CARD =
  /(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)/g;

const SENSITIVE_WORDS_ZH = [
  '明文密码',
  '管理员密码',
  '登录密码',
  '数据库密码',
  'root密码',
  'root口令',
  '签名密钥',
  '访问密钥',
  '加密密钥',
  '主密钥',
  '密钥对',
  '连接字符串',
  '连接串',
  '敏感信息',
  '暴力破解',
  '字典扫描',
  '特权账号',
  '特权账户',
  '渗透测试',
  '勒索软件',
  '漏洞利用',
  '内网穿透',
  '科学上网',
  '机场节点',
  '代理节点',
  '代理机场',
  '订阅链接',
  '节点订阅',
  '密码',
  '口令',
  '私钥',
  '公钥',
  '密钥',
  '秘钥',
  '令牌',
  '凭据',
  '凭证',
  '鉴权码',
  '授权码',
  '校验码',
  '验证码',
  '机密',
  '绝密',
  '密文',
  '爆破',
  '提权',
  '后门',
  '木马',
  '肉鸡',
  '挖矿',
  '矿机',
  '渗透',
  '黑客',
  '暗网',
  '堡垒机',
  '跳板机',
  '翻墙',
  '梯子',
];

const SENSITIVE_WORDS_EN_SUBTOKEN = [
  'PasswordAuthentication',
  'PermitRootLogin',
  'AuthorizedKeysFile',
  'encryption_key',
  'webhook_secret',
  'refresh_token',
  'client_secret',
  'access_token',
  'private_key',
  'public_key',
  'secret_key',
  'master_key',
  'access_key',
  'auth_token',
  'app_secret',
  'signing_key',
  'passphrase',
  'credentials',
  'credential',
  'shadowsocks',
  'password',
  'wireguard',
  'hysteria2',
  'hysteria',
  'tailscale',
  'zerotier',
  'cloudflared',
  'metasploit',
  'cobaltstrike',
  'mimikatz',
  'sing-box',
  'singbox',
  'openvpn',
  'api_key',
  'apikey',
  'api key',
  'private key',
  'passwd',
  'secret',
  'trojan',
  'socks5',
  'mihomo',
  'sqlmap',
  'webhook',
  'xmrig',
  'v2ray',
  'clash',
  'vmess',
  'vless',
  'ngrok',
  'token',
  'xray',
  'frpc',
  'frps',
  'tuic',
  'vpn',
  'wg0',
];

const SENSITIVE_WORDS_EN_WORD = [
  'root',
  'bearer',
  'jwt',
  'oauth',
  'cookie',
  'htpasswd',
  'shadow',
  'sudoers',
  'hydra',
  'nmap',
];

const GENERIC_NON_SECRET_USERNAMES = new Set([
  'ubuntu',
  'debian',
  'centos',
  'fedora',
  'alpine',
  'rocky',
  'alma',
  'arch',
  'linux',
  'macos',
  'darwin',
  'docker',
  'nginx',
  'redis',
  'mysql',
  'postgres',
  'postgresql',
  'system',
  'server',
  'service',
  'monitor',
  'agent',
  'user',
  'admin',
  'root',
]);

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const RE_SENSITIVE_ZH = new RegExp(
  SENSITIVE_WORDS_ZH.map((w) => escapeRegExp(w)).join('|'),
  'gi'
);

const RE_SENSITIVE_EN_SUBTOKEN = new RegExp(
  `(?<![A-Za-z0-9])(?:${SENSITIVE_WORDS_EN_SUBTOKEN.map((w) => escapeRegExp(w)).join('|')})(?![A-Za-z0-9])`,
  'gi'
);

const RE_SENSITIVE_EN_WORD = new RegExp(
  `\\b(?:${SENSITIVE_WORDS_EN_WORD.map((w) => escapeRegExp(w)).join('|')})\\b`,
  'gi'
);

const RE_PORTS_NOTE_BARE_PORT =
  /(?<![A-Za-z0-9._-])(\d{1,5}(?:-\d{1,5})?)(?![A-Za-z0-9._%-])/g;

function isValidPortNum(raw: string): boolean {
  if (!/^[1-9]\d{0,4}$/.test(raw)) return false;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

function isValidPortSpec(spec: string): boolean {
  const parts = spec.split(/[:-]/);
  return parts.length > 0 && parts.every((p) => isValidPortNum(p));
}

function maskPortListStr(listStr: string, sentinel: string): string {
  return listStr.replace(/\d{1,5}(?:-\d{1,5})?/g, (token) =>
    isValidPortSpec(token) ? sentinel : token
  );
}

function pickUniqueSentinel(raw: string): string {
  if (!raw.includes(DEFAULT_MASK_SENTINEL)) {
    return DEFAULT_MASK_SENTINEL;
  }
  let idx = 1;
  while (raw.includes(`\uE000SNS_MASK_${idx}\uE001`)) {
    idx += 1;
  }
  return `\uE000SNS_MASK_${idx}\uE001`;
}

function replaceTrimmingTrailingPunct(match: string, sentinel: string): string {
  let end = match.length;
  while (end > 0 && /[)\].,;!?]/.test(match[end - 1])) {
    end -= 1;
  }
  if (end === 0) return match;
  return sentinel + match.slice(end);
}

interface CompiledDynamicPatterns {
  knownPathRegex: RegExp | null;
  knownHostRegex: RegExp | null;
  knownUserRegex: RegExp | null;
  knownPortRegex: RegExp | null;
}

function compileDynamicPatterns(ctx?: SensitiveMaskContext): CompiledDynamicPatterns {
  const pathSet = new Set<string>();
  const hostSet = new Set<string>();
  const userSet = new Set<string>();
  const portSet = new Set<number>();

  for (const srv of ctx?.servers || []) {
    const h = (srv.host || '').trim();
    if (h.length >= 2) hostSet.add(h);

    const dp = (srv.default_path || '').trim();
    if (dp.length >= 2 && dp !== '/') pathSet.add(dp);

    const u = (srv.username || '').trim();
    if (u.length >= 3 && !GENERIC_NON_SECRET_USERNAMES.has(u.toLowerCase())) {
      userSet.add(u);
    }

    if (
      typeof srv.port === 'number' &&
      Number.isInteger(srv.port) &&
      srv.port >= 1024 &&
      srv.port <= 65535 &&
      (srv.port < 1990 || srv.port > 2099)
    ) {
      portSet.add(srv.port);
    }
  }

  for (const hm of ctx?.hostMemories || []) {
    for (const dp of hm.deploy_paths || []) {
      const clean = (dp || '').trim();
      if (clean.length >= 2 && clean !== '/') {
        pathSet.add(clean);
      }
    }
  }

  const sortLongestFirst = (items: Iterable<string>) =>
    Array.from(items).sort((a, b) => b.length - a.length);

  const paths = sortLongestFirst(pathSet);
  const hosts = sortLongestFirst(hostSet);
  const users = sortLongestFirst(userSet);
  const ports = Array.from(portSet).sort((a, b) => b - a);

  return {
    knownPathRegex:
      paths.length > 0
        ? new RegExp(
            `(?<![A-Za-z0-9_/-])(?:${paths.map(escapeRegExp).join('|')})(?:\\/[A-Za-z0-9._~@%+\\-/]*)?(?![A-Za-z0-9_.-])`,
            'g'
          )
        : null,
    knownHostRegex:
      hosts.length > 0
        ? new RegExp(
            `(?<![A-Za-z0-9_.-])(?:${hosts.map(escapeRegExp).join('|')})(?::\\d{1,5})?(?![A-Za-z0-9_.-])`,
            'gi'
          )
        : null,
    knownUserRegex:
      users.length > 0
        ? new RegExp(
            `(?<![A-Za-z0-9_-])(?:${users.map(escapeRegExp).join('|')})(?![A-Za-z0-9_-])`,
            'gi'
          )
        : null,
    knownPortRegex:
      ports.length > 0
        ? new RegExp(
            `(?<![A-Za-z0-9._:-])(?:${ports.map((p) => String(p)).join('|')})(?![A-Za-z0-9._%-])(?![ \\t]*(?:MB|GB|KB|TB|ms|px|次|条|台|个|字符))`,
            'g'
          )
        : null,
  };
}

function applyMaskPipeline(
  raw: string,
  sentinel: string,
  dyn: CompiledDynamicPatterns
): string {
  if (!raw) return '';

  let out = raw;

  // 1. Multi-line private keys / certificates
  out = out.replace(RE_PEM_BLOCK, sentinel);

  // 2. Full URIs & database/proxy connection strings
  out = out.replace(RE_URI, (m) => replaceTrimmingTrailingPunct(m, sentinel));

  // 3. SSH public keys, fingerprints, auth tokens, cloud keys, ARNs, resource IDs, UUIDs, long hex secrets
  out = out.replace(RE_SSH_PUBKEY, sentinel);
  out = out.replace(RE_SSH_FINGERPRINT, sentinel);
  out = out.replace(RE_AUTH_HEADER_VALUE, sentinel);
  out = out.replace(RE_JWT, sentinel);
  out = out.replace(RE_WELL_KNOWN_TOKENS, sentinel);
  out = out.replace(RE_CLOUD_ARN, sentinel);
  out = out.replace(RE_CLOUD_RESOURCE_ID, sentinel);
  out = out.replace(RE_UUID, sentinel);
  out = out.replace(RE_LONG_HEX, sentinel);

  // 4. Dynamic server metadata from active inventory & host profiles
  if (dyn.knownPathRegex) {
    out = out.replace(dyn.knownPathRegex, sentinel);
  }
  if (dyn.knownHostRegex) {
    out = out.replace(dyn.knownHostRegex, sentinel);
  }
  if (dyn.knownUserRegex) {
    out = out.replace(dyn.knownUserRegex, sentinel);
  }

  // 5. CLI credential flags & inline KV secret assignments (EN + ZH)
  out = out.replace(RE_CLI_AUTH_HEADER, `$1${sentinel}`);
  out = out.replace(RE_CLI_SECRET_FLAG, `$1${sentinel}`);
  out = out.replace(RE_CLI_MYSQL_PASS, `$1${sentinel}`);
  out = out.replace(RE_CLI_REDIS_PASS, `$1${sentinel}`);
  out = out.replace(RE_CLI_CURL_USER, `$1${sentinel}`);

  out = out.replace(
    RE_KV_EN,
    (_m, b1: string | undefined, b2: string | undefined, sep: string) =>
      b1 && b2 ? `**${sentinel}**${sep}${sentinel}` : sentinel
  );
  out = out.replace(RE_ENV_SECRET_KV, sentinel);
  out = out.replace(RE_SSH_CONFIG_DIRECTIVE, `$1${sentinel}`);
  out = out.replace(RE_SERVER_FIELD_ZH, `$1${sentinel}`);
  out = out.replace(
    RE_KV_ZH_COLON,
    (_m, b1: string | undefined, b2: string | undefined, sep: string) =>
      b1 && b2 ? `**${sentinel}**${sep}${sentinel}` : sentinel
  );
  out = out.replace(
    RE_KV_ZH_IS,
    (_m, b1: string | undefined, b2: string | undefined, verb: string) =>
      b1 && b2 ? `**${sentinel}**${verb} ${sentinel}` : sentinel
  );

  // 6. Emails & SSH user@host
  out = out.replace(RE_EMAIL, sentinel);
  out = out.replace(RE_SSH_USER_HOST_IP, sentinel);
  out = out.replace(RE_SSH_CMD_USER_HOST, `$1${sentinel}`);
  out = out.replace(RE_COMMON_USER_AT_HOST, sentinel);

  // 7. IPv6, IPv4, CIDR, wildcard IPv4 & MAC addresses
  out = out.replace(RE_IPV6_BRACKET, sentinel);
  out = out.replace(RE_IPV6_FULL, sentinel);
  out = out.replace(RE_IPV6_COMPRESSED, sentinel);
  out = out.replace(RE_IPV6_UNSPEC, sentinel);
  out = out.replace(RE_IPV4, sentinel);
  out = out.replace(RE_IPV4_WILDCARD, (m) => {
    if (!m.includes('*')) return m;
    const numericCount = m.split('.').filter((seg) => /^\d+$/.test(seg)).length;
    return numericCount >= 2 ? sentinel : m;
  });
  out = out.replace(RE_MAC, sentinel);

  // 8. Domains / FQDNs (excluding non-TLD filenames like AGENTS.md)
  out = out.replace(RE_DOMAIN, sentinel);

  // 9. File & deployment paths (Windows, home/relative, Unix absolute, sensitive config/log files)
  out = out.replace(RE_WIN_PATH, (m) => replaceTrimmingTrailingPunct(m, sentinel));
  out = out.replace(RE_WIN_SLASH_PATH, (m) => replaceTrimmingTrailingPunct(m, sentinel));
  out = out.replace(RE_HOME_OR_DOT_PATH, (m) => replaceTrimmingTrailingPunct(m, sentinel));
  out = out.replace(RE_UNIX_MULTI_PATH, (m) => replaceTrimmingTrailingPunct(m, sentinel));
  out = out.replace(RE_UNIX_TOP_DIR, sentinel);
  out = out.replace(RE_REL_FILE_PATH, sentinel);
  out = out.replace(RE_SENSITIVE_FILENAME, sentinel);
  out = out.replace(RE_DOTENV_FILE, sentinel);

  // 10. Ports (protocol/port, bind:port, CLI port flags, labeled Chinese/English ports)
  out = out.replace(RE_PROTO_PORT, (m, p: string) => (isValidPortSpec(p) ? sentinel : m));
  out = out.replace(RE_PORT_PROTO, (m, p: string) => (isValidPortSpec(p) ? sentinel : m));
  out = out.replace(RE_BIND_HOST_PORT, (m, p: string) => (isValidPortSpec(p) ? sentinel : m));
  out = out.replace(RE_SERVICE_PORT, (m, svc: string, p: string) =>
    isValidPortNum(p) ? `${svc}:${sentinel}` : m
  );
  out = out.replace(RE_STANDALONE_COLON_PORT, (m, p: string) =>
    isValidPortNum(p) ? `:${sentinel}` : m
  );
  out = out.replace(RE_CLI_PORT_FLAG, (m, prefix: string, p: string) =>
    isValidPortSpec(p) ? `${prefix}${sentinel}` : m
  );
  out = out.replace(RE_UFW_PORT, (m, prefix: string, p: string) =>
    isValidPortSpec(p) ? `${prefix}${sentinel}` : m
  );
  out = out.replace(RE_PORT_PREFIX_LABEL, (_m, prefix: string, list: string) =>
    `${prefix}${maskPortListStr(list, sentinel)}`
  );
  out = out.replace(RE_PORT_SUFFIX_LABEL, (_m, list: string, suffix: string) =>
    `${maskPortListStr(list, sentinel)}${suffix}`
  );
  out = out.replace(RE_PORT_VERB_ZH, (_m, prefix: string, list: string) =>
    `${prefix}${maskPortListStr(list, sentinel)}`
  );
  if (dyn.knownPortRegex) {
    out = out.replace(dyn.knownPortRegex, sentinel);
  }

  // 11. Personal contact & identity identifiers
  out = out.replace(RE_CN_ID_CARD, sentinel);
  out = out.replace(RE_CN_PHONE, sentinel);

  // 12. Curated Chinese & English sensitive ops/security/network vocabulary
  out = out.replace(RE_SENSITIVE_ZH, sentinel);
  out = out.replace(RE_SENSITIVE_EN_SUBTOKEN, sentinel);
  out = out.replace(RE_SENSITIVE_EN_WORD, sentinel);

  // 13. Collapse compound host:port sentinel pairs like <M>:<M> -> <M>
  const escapedSentinel = escapeRegExp(sentinel);
  const reCollapseColon = new RegExp(`${escapedSentinel}:${escapedSentinel}`, 'g');
  out = out.replace(reCollapseColon, sentinel);

  return out;
}

export function createSensitiveMasker(ctx?: SensitiveMaskContext): SensitiveMasker {
  const dyn = compileDynamicPatterns(ctx);

  const maskMarkdownWithSentinel = (raw: string): { masked: string; sentinel: string } => {
    if (!raw) return { masked: '', sentinel: DEFAULT_MASK_SENTINEL };
    const sentinel = pickUniqueSentinel(raw);
    const masked = applyMaskPipeline(raw, sentinel, dyn);
    return { masked, sentinel };
  };

  const maskText = (raw: string): string => {
    if (!raw) return '';
    const { masked, sentinel } = maskMarkdownWithSentinel(raw);
    const escapedSentinel = escapeRegExp(sentinel);
    const normalized = masked.replace(
      new RegExp(`\\*\\*${escapedSentinel}\\*\\*`, 'g'),
      sentinel
    );
    return normalized.split(sentinel).join(MASK_PLACEHOLDER);
  };

  const maskPortsNote = (raw: string): string => {
    if (!raw) return '';
    const sentinel = pickUniqueSentinel(raw);
    let masked = applyMaskPipeline(raw, sentinel, dyn);
    masked = masked.replace(RE_PORTS_NOTE_BARE_PORT, (m, token: string) =>
      isValidPortSpec(token) ? sentinel : m
    );
    const escapedSentinel = escapeRegExp(sentinel);
    masked = masked.replace(new RegExp(`${escapedSentinel}:${escapedSentinel}`, 'g'), sentinel);
    return masked.split(sentinel).join(MASK_PLACEHOLDER);
  };

  const maskDeployPath = (raw: string): string => {
    if (!raw || !raw.trim()) return '';
    return MASK_PLACEHOLDER;
  };

  const maskServiceName = (raw: string): string => {
    if (!raw) return '';
    const trimmed = raw.trim();
    if (trimmed.toLowerCase().startsWith('container:')) {
      return `container:${MASK_PLACEHOLDER}`;
    }
    return maskText(raw);
  };

  const maskServerName = (raw: string): string => {
    if (!raw) return '';
    return maskText(raw);
  };

  return {
    maskText,
    maskMarkdownWithSentinel,
    maskPortsNote,
    maskDeployPath,
    maskServiceName,
    maskServerName,
  };
}

export function maskSensitiveText(raw: string, ctx?: SensitiveMaskContext): string {
  return createSensitiveMasker(ctx).maskText(raw);
}
