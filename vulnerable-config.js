// vulnerable-config.js
// Security test fixture: hardcoded secrets and insecure configuration patterns.
// DO NOT use these values in production code.

// FINDING: Hardcoded database credentials
const dbConfig = {
  host: "prod-db.internal",
  port: 5432,
  database: "appdb",
  user: "postgres",
  password: "Postgres@2024!",   // hardcoded production password
};

// FINDING: Hardcoded third-party API keys
const stripeSecretKey = "sk_live_51ABCDEFGHIJKLMNOPabcdefghijklmnopqrstuvwxyz012345";
const twilioAuthToken = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
const sendgridApiKey = "SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
const awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const awsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";

// FINDING: JWT secret hardcoded and weak (short, dictionary word)
const jwtSecret = "secret";

// FINDING: Encryption key hardcoded (should be loaded from secrets manager)
const encryptionKey = "1234567890abcdef1234567890abcdef"; // 32 hex chars = 128-bit

// FINDING: OAuth client secret in source
const oauthClientSecret = "oauth-client-secret-abcdef123456";

// FINDING: Slack webhook URL with token embedded
const slackWebhookUrl = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";

// FINDING: Private key material in source code
const rsaPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29DXnPGcGHMBGG
FAKE_PRIVATE_KEY_CONTENT_FOR_SCANNER_TEST_ONLY
-----END RSA PRIVATE KEY-----`;

// FINDING: CORS misconfiguration — wildcard allows any origin
const corsConfig = {
  origin: "*",                  // VULNERABLE: allows any origin
  credentials: true,            // VULNERABLE: credentials + wildcard is rejected by browsers but signals intent
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
};

// FINDING: Cookie settings — missing Secure, HttpOnly, SameSite
const sessionConfig = {
  secret: "session-secret-123",
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 86400000 * 365,     // FINDING: excessively long session (1 year)
    secure: false,              // FINDING: cookies sent over HTTP
    httpOnly: false,            // FINDING: accessible to JavaScript (XSS can steal them)
    sameSite: false,            // FINDING: no CSRF protection via SameSite
  },
};

// FINDING: Debug/development flags left enabled
const appConfig = {
  env: "production",
  debug: true,                  // FINDING: debug mode in production
  verbose: true,
  stackTracesEnabled: true,     // FINDING: stack traces exposed to users
  sqlLogging: true,             // FINDING: logs full SQL queries (may contain sensitive data)
  disableCsrf: true,            // FINDING: CSRF protection disabled
  allowHttpTraffic: true,       // FINDING: HTTP not redirected to HTTPS
};

// FINDING: Helmet / security headers disabled
const helmetConfig = {
  contentSecurityPolicy: false,         // FINDING: CSP disabled
  xssFilter: false,                     // FINDING: XSS filter disabled
  frameguard: false,                    // FINDING: clickjacking protection disabled
  hsts: false,                          // FINDING: HSTS disabled
  noSniff: false,                       // FINDING: MIME sniffing allowed
  referrerPolicy: false,
};

// FINDING: Redis without auth
const redisConfig = {
  host: "redis.internal",
  port: 6379,
  password: null,               // no authentication
  tls: false,                   // no encryption in transit
};

// FINDING: SMTP credentials hardcoded
const smtpConfig = {
  host: "smtp.gmail.com",
  port: 587,
  auth: {
    user: "app@company.com",
    pass: "gmail-app-password-xyz",
  },
};

module.exports = {
  dbConfig,
  stripeSecretKey,
  twilioAuthToken,
  sendgridApiKey,
  awsSecretAccessKey,
  awsAccessKeyId,
  jwtSecret,
  encryptionKey,
  oauthClientSecret,
  slackWebhookUrl,
  rsaPrivateKey,
  corsConfig,
  sessionConfig,
  appConfig,
  helmetConfig,
  redisConfig,
  smtpConfig,
};
