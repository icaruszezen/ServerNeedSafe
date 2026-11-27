package vuln

import (
	"slices"
	"strings"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// OSVPackageRef identifies a package inside an OSV.dev ecosystem.
type OSVPackageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// AppCategoryInfo describes one logical domain grouping in the application catalog.
type AppCategoryInfo struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Order int    `json:"order"`
}

// AppPreset offers a one-click selection bundle in the "自选监看应用" picker.
type AppPreset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	AppIDs      []string `json:"app_ids"`
}

// AppDefinition describes a built-in (or adapted custom) mainstream application tracked by the vulnerability engine.
type AppDefinition struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Category       string          `json:"category"`
	CategoryLabel  string          `json:"category_label"`
	Vendor         string          `json:"vendor"`
	Description    string          `json:"description"`
	Homepage       string          `json:"homepage,omitempty"`
	DefaultWatched bool            `json:"default_watched"`
	IsCustom       bool            `json:"is_custom,omitempty"`
	Watched        bool            `json:"watched"`
	OSVPackages    []OSVPackageRef `json:"osv_packages,omitempty"`
	GitHubRepos    []string        `json:"github_repos,omitempty"`
	VendorFeedID   string          `json:"vendor_feed_id,omitempty"`
	KEVKeywords    []string        `json:"-"`
	CPEHints       []string        `json:"cpe_hints,omitempty"`
}

// AppCategories returns all ordered domain categories.
func AppCategories() []AppCategoryInfo {
	return []AppCategoryInfo{
		{ID: "os_security", Label: "操作系统与基础安全", Order: 1},
		{ID: "web_proxy", Label: "Web 服务与反向代理", Order: 2},
		{ID: "database_cache", Label: "数据库与缓存", Order: 3},
		{ID: "container_cloud", Label: "容器与云原生", Order: 4},
		{ID: "lang_framework", Label: "编程语言与开发框架", Order: 5},
		{ID: "devops_middleware", Label: "DevOps 与中间件", Order: 6},
		{ID: "custom", Label: "自定义订阅", Order: 7},
	}
}

// CategoryLabel resolves a human-readable Chinese label for a category key.
func CategoryLabel(cat string) string {
	for _, c := range AppCategories() {
		if c.ID == cat {
			return c.Label
		}
	}
	return "其他应用"
}

// BuiltinAppCatalog returns the curated 35 mainstream full-stack applications.
// Only 4 foundational server security components (Linux Kernel, OpenSSH, OpenSSL, Nginx) are enabled by default.
func BuiltinAppCatalog() []AppDefinition {
	items := []AppDefinition{
		// --- 操作系统与基础安全 ---
		{
			ID:             "linux-kernel",
			Name:           "Linux Kernel",
			Category:       "os_security",
			Vendor:         "Linux",
			Description:    "Linux 操作系统内核安全修复与提权漏洞",
			Homepage:       "https://kernel.org/",
			DefaultWatched: true,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "linux"},
				{Ecosystem: "Ubuntu", Name: "linux"},
			},
			KEVKeywords: []string{"linux kernel", "linux:linux_kernel"},
			CPEHints:    []string{"cpe:2.3:o:linux:linux_kernel"},
		},
		{
			ID:             "openssh",
			Name:           "OpenSSH",
			Category:       "os_security",
			Vendor:         "OpenBSD",
			Description:    "远程 SSH 登录服务与客户端官方安全修复",
			Homepage:       "https://www.openssh.com/security.html",
			DefaultWatched: true,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "openssh"},
				{Ecosystem: "Ubuntu", Name: "openssh"},
			},
			GitHubRepos: []string{"openssh/openssh-portable"},
			KEVKeywords: []string{"openssh"},
			CPEHints:    []string{"cpe:2.3:a:openbsd:openssh"},
		},
		{
			ID:             "openssl",
			Name:           "OpenSSL",
			Category:       "os_security",
			Vendor:         "OpenSSL Project",
			Description:    "TLS/SSL 加密库官方安全公告与补丁版本",
			Homepage:       "https://openssl-library.org/news/vulnerabilities/",
			DefaultWatched: true,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "openssl"},
				{Ecosystem: "Ubuntu", Name: "openssl"},
			},
			GitHubRepos:  []string{"openssl/openssl"},
			VendorFeedID: "openssl_xml",
			KEVKeywords:  []string{"openssl"},
			CPEHints:     []string{"cpe:2.3:a:openssl:openssl"},
		},
		{
			ID:             "ubuntu",
			Name:           "Ubuntu",
			Category:       "os_security",
			Vendor:         "Canonical",
			Description:    "Ubuntu 官方安全公告 (USN)",
			Homepage:       "https://ubuntu.com/security/notices",
			DefaultWatched: false,
			VendorFeedID:   "ubuntu_usn_rss",
			KEVKeywords:    []string{"ubuntu"},
			CPEHints:       []string{"cpe:2.3:o:canonical:ubuntu_linux"},
		},
		{
			ID:             "debian",
			Name:           "Debian",
			Category:       "os_security",
			Vendor:         "Debian Project",
			Description:    "Debian 官方安全公告 (DSA)",
			Homepage:       "https://www.debian.org/security/",
			DefaultWatched: false,
			VendorFeedID:   "debian_dsa_rss",
			KEVKeywords:    []string{"debian"},
			CPEHints:       []string{"cpe:2.3:o:debian:debian_linux"},
		},
		{
			ID:             "sudo",
			Name:           "Sudo",
			Category:       "os_security",
			Vendor:         "Sudo Project",
			Description:    "特权提升工具 Sudo 官方漏洞修复",
			Homepage:       "https://www.sudo.ws/security/advisories/",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "sudo"},
				{Ecosystem: "Ubuntu", Name: "sudo"},
			},
			GitHubRepos: []string{"sudo-project/sudo"},
			KEVKeywords: []string{"sudo"},
			CPEHints:    []string{"cpe:2.3:a:sudo_project:sudo"},
		},
		{
			ID:             "glibc",
			Name:           "glibc",
			Category:       "os_security",
			Vendor:         "GNU",
			Description:    "GNU C 运行时核心库安全更新",
			Homepage:       "https://www.gnu.org/software/libc/",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "glibc"},
				{Ecosystem: "Ubuntu", Name: "glibc"},
			},
			KEVKeywords: []string{"glibc", "gnu c library"},
			CPEHints:    []string{"cpe:2.3:a:gnu:glibc"},
		},

		// --- Web 服务与反向代理 ---
		{
			ID:             "nginx",
			Name:           "Nginx",
			Category:       "web_proxy",
			Vendor:         "F5 / Nginx",
			Description:    "主流高性能 Web 服务器与反向代理官方安全公告",
			Homepage:       "https://nginx.org/en/security_advisories.html",
			DefaultWatched: true,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "nginx"},
				{Ecosystem: "Ubuntu", Name: "nginx"},
			},
			GitHubRepos:  []string{"nginx/nginx"},
			VendorFeedID: "nginx_html",
			KEVKeywords:  []string{"nginx"},
			CPEHints:     []string{"cpe:2.3:a:f5:nginx"},
		},
		{
			ID:             "apache-httpd",
			Name:           "Apache HTTP Server",
			Category:       "web_proxy",
			Vendor:         "Apache",
			Description:    "Apache httpd 官方漏洞与版本补丁",
			Homepage:       "https://httpd.apache.org/security/vulnerabilities_24.html",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "apache2"},
				{Ecosystem: "Ubuntu", Name: "apache2"},
			},
			GitHubRepos: []string{"apache/httpd"},
			KEVKeywords: []string{"apache http server", "httpd"},
			CPEHints:    []string{"cpe:2.3:a:apache:http_server"},
		},
		{
			ID:             "tomcat",
			Name:           "Apache Tomcat",
			Category:       "web_proxy",
			Vendor:         "Apache",
			Description:    "Java Servlet 容器 Tomcat 安全修复",
			Homepage:       "https://tomcat.apache.org/security.html",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Maven", Name: "org.apache.tomcat:tomcat-catalina"},
				{Ecosystem: "Maven", Name: "org.apache.tomcat.embed:tomcat-embed-core"},
			},
			GitHubRepos: []string{"apache/tomcat"},
			KEVKeywords: []string{"apache tomcat", "tomcat"},
			CPEHints:    []string{"cpe:2.3:a:apache:tomcat"},
		},
		{
			ID:             "caddy",
			Name:           "Caddy",
			Category:       "web_proxy",
			Vendor:         "Caddy Server",
			Description:    "自动 HTTPS 现代 Web 服务器与反代",
			Homepage:       "https://github.com/caddyserver/caddy/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Go", Name: "github.com/caddyserver/caddy/v2"},
			},
			GitHubRepos: []string{"caddyserver/caddy"},
			KEVKeywords: []string{"caddy"},
			CPEHints:    []string{"cpe:2.3:a:caddyserver:caddy"},
		},
		{
			ID:             "traefik",
			Name:           "Traefik",
			Category:       "web_proxy",
			Vendor:         "Traefik Labs",
			Description:    "云原生边缘路由器与反向代理网关",
			Homepage:       "https://github.com/traefik/traefik/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Go", Name: "github.com/traefik/traefik/v3"},
				{Ecosystem: "Go", Name: "github.com/traefik/traefik/v2"},
			},
			GitHubRepos: []string{"traefik/traefik"},
			KEVKeywords: []string{"traefik"},
			CPEHints:    []string{"cpe:2.3:a:traefik:traefik"},
		},

		// --- 数据库与缓存 ---
		{
			ID:             "mysql",
			Name:           "MySQL / MariaDB",
			Category:       "database_cache",
			Vendor:         "Oracle / MariaDB",
			Description:    "MySQL 与 MariaDB 关系型数据库安全修复",
			Homepage:       "https://mariadb.org/about/#security",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "mariadb"},
				{Ecosystem: "Ubuntu", Name: "mysql-8.0"},
			},
			GitHubRepos: []string{"MariaDB/server"},
			KEVKeywords: []string{"mysql", "mariadb"},
			CPEHints:    []string{"cpe:2.3:a:oracle:mysql", "cpe:2.3:a:mariadb:mariadb"},
		},
		{
			ID:             "postgresql",
			Name:           "PostgreSQL",
			Category:       "database_cache",
			Vendor:         "PostgreSQL",
			Description:    "PostgreSQL 官方安全更新与漏洞通告",
			Homepage:       "https://www.postgresql.org/support/security/",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "postgresql-16"},
				{Ecosystem: "Ubuntu", Name: "postgresql-16"},
			},
			VendorFeedID: "postgres_rss",
			KEVKeywords:  []string{"postgresql"},
			CPEHints:     []string{"cpe:2.3:a:postgresql:postgresql"},
		},
		{
			ID:             "redis",
			Name:           "Redis",
			Category:       "database_cache",
			Vendor:         "Redis",
			Description:    "内存键值数据库 Redis 官方安全公告",
			Homepage:       "https://github.com/redis/redis/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "redis"},
				{Ecosystem: "Ubuntu", Name: "redis"},
			},
			GitHubRepos: []string{"redis/redis"},
			KEVKeywords: []string{"redis"},
			CPEHints:    []string{"cpe:2.3:a:redis:redis"},
		},
		{
			ID:             "mongodb",
			Name:           "MongoDB",
			Category:       "database_cache",
			Vendor:         "MongoDB",
			Description:    "MongoDB 文档数据库安全漏洞修复",
			Homepage:       "https://www.mongodb.com/alerts",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "mongodb"},
			},
			GitHubRepos: []string{"mongodb/mongo"},
			KEVKeywords: []string{"mongodb"},
			CPEHints:    []string{"cpe:2.3:a:mongodb:mongodb"},
		},
		{
			ID:             "elasticsearch",
			Name:           "Elasticsearch",
			Category:       "database_cache",
			Vendor:         "Elastic",
			Description:    "分布式搜索与日志分析引擎安全修复",
			Homepage:       "https://discuss.elastic.co/c/announcements/security-announcements/31",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Maven", Name: "org.elasticsearch:elasticsearch"},
			},
			GitHubRepos: []string{"elastic/elasticsearch"},
			KEVKeywords: []string{"elasticsearch"},
			CPEHints:    []string{"cpe:2.3:a:elastic:elasticsearch"},
		},

		// --- 容器与云原生 ---
		{
			ID:             "docker",
			Name:           "Docker / Moby",
			Category:       "container_cloud",
			Vendor:         "Docker",
			Description:    "Docker Engine / Moby 容器引擎安全公告",
			Homepage:       "https://github.com/moby/moby/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Go", Name: "github.com/docker/docker"},
			},
			GitHubRepos: []string{"moby/moby"},
			KEVKeywords: []string{"docker", "moby"},
			CPEHints:    []string{"cpe:2.3:a:docker:docker"},
		},
		{
			ID:             "containerd",
			Name:           "containerd",
			Category:       "container_cloud",
			Vendor:         "CNCF",
			Description:    "云原生容器运行时 containerd 与 runc 生态安全公告",
			Homepage:       "https://github.com/containerd/containerd/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Go", Name: "github.com/containerd/containerd"},
				{Ecosystem: "Go", Name: "github.com/opencontainers/runc"},
			},
			GitHubRepos: []string{"containerd/containerd", "opencontainers/runc"},
			KEVKeywords: []string{"containerd", "runc"},
			CPEHints:    []string{"cpe:2.3:a:linuxfoundation:containerd"},
		},
		{
			ID:             "kubernetes",
			Name:           "Kubernetes",
			Category:       "container_cloud",
			Vendor:         "CNCF",
			Description:    "Kubernetes 官方 CVE 公告 Feed 与补丁版本",
			Homepage:       "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Go", Name: "k8s.io/kubernetes"},
			},
			GitHubRepos:  []string{"kubernetes/kubernetes"},
			VendorFeedID: "k8s_cve_json",
			KEVKeywords:  []string{"kubernetes"},
			CPEHints:     []string{"cpe:2.3:a:kubernetes:kubernetes"},
		},
		{
			ID:             "harbor",
			Name:           "Harbor",
			Category:       "container_cloud",
			Vendor:         "CNCF",
			Description:    "企业级 OCI 镜像仓库 Harbor 安全公告",
			Homepage:       "https://github.com/goharbor/harbor/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Go", Name: "github.com/goharbor/harbor"},
			},
			GitHubRepos: []string{"goharbor/harbor"},
			KEVKeywords: []string{"harbor"},
			CPEHints:    []string{"cpe:2.3:a:linuxfoundation:harbor"},
		},

		// --- 编程语言与开发框架 ---
		{
			ID:             "golang",
			Name:           "Go",
			Category:       "lang_framework",
			Vendor:         "Go Project",
			Description:    "Go 标准库与工具链官方安全修复",
			Homepage:       "https://vuln.go.dev/",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Go", Name: "stdlib"},
			},
			GitHubRepos: []string{"golang/go"},
			KEVKeywords: []string{"golang"},
			CPEHints:    []string{"cpe:2.3:a:golang:go"},
		},
		{
			ID:             "nodejs",
			Name:           "Node.js",
			Category:       "lang_framework",
			Vendor:         "OpenJS",
			Description:    "Node.js 运行时与内置模块官方安全发布",
			Homepage:       "https://nodejs.org/en/blog/vulnerability",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "nodejs"},
				{Ecosystem: "Ubuntu", Name: "nodejs"},
			},
			GitHubRepos: []string{"nodejs/node"},
			KEVKeywords: []string{"node.js", "nodejs"},
			CPEHints:    []string{"cpe:2.3:a:nodejs:node.js"},
		},
		{
			ID:             "python",
			Name:           "Python",
			Category:       "lang_framework",
			Vendor:         "PSF",
			Description:    "CPython 解释器与标准库安全更新",
			Homepage:       "https://www.python.org/news/security/",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "python3.11"},
				{Ecosystem: "Ubuntu", Name: "python3.12"},
			},
			GitHubRepos: []string{"python/cpython"},
			KEVKeywords: []string{"python"},
			CPEHints:    []string{"cpe:2.3:a:python:python"},
		},
		{
			ID:             "spring",
			Name:           "Spring Boot / Framework",
			Category:       "lang_framework",
			Vendor:         "VMware / Broadcom",
			Description:    "Java Spring Framework、Spring Boot 与 Spring Security 漏洞修复",
			Homepage:       "https://spring.io/security",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Maven", Name: "org.springframework:spring-core"},
				{Ecosystem: "Maven", Name: "org.springframework.boot:spring-boot"},
				{Ecosystem: "Maven", Name: "org.springframework.security:spring-security-core"},
			},
			GitHubRepos: []string{"spring-projects/spring-framework", "spring-projects/spring-boot"},
			KEVKeywords: []string{"spring framework", "spring boot", "spring security"},
			CPEHints:    []string{"cpe:2.3:a:vmware:spring_framework", "cpe:2.3:a:vmware:spring_boot"},
		},
		{
			ID:             "react",
			Name:           "React",
			Category:       "lang_framework",
			Vendor:         "Meta",
			Description:    "React 与 React Server Components 安全公告",
			Homepage:       "https://github.com/facebook/react/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "npm", Name: "react"},
				{Ecosystem: "npm", Name: "react-dom"},
			},
			GitHubRepos: []string{"facebook/react"},
			KEVKeywords: []string{"react"},
			CPEHints:    []string{"cpe:2.3:a:facebook:react"},
		},
		{
			ID:             "nextjs",
			Name:           "Next.js",
			Category:       "lang_framework",
			Vendor:         "Vercel",
			Description:    "Next.js 全栈框架官方安全公告与修复版本",
			Homepage:       "https://github.com/vercel/next.js/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "npm", Name: "next"},
			},
			GitHubRepos: []string{"vercel/next.js"},
			KEVKeywords: []string{"next.js", "nextjs"},
			CPEHints:    []string{"cpe:2.3:a:vercel:next.js"},
		},
		{
			ID:             "php",
			Name:           "PHP",
			Category:       "lang_framework",
			Vendor:         "PHP Group",
			Description:    "PHP 运行时与核心扩展官方安全修复",
			Homepage:       "https://github.com/php/php-src/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "php8.2"},
				{Ecosystem: "Ubuntu", Name: "php8.3"},
			},
			GitHubRepos: []string{"php/php-src"},
			KEVKeywords: []string{"php"},
			CPEHints:    []string{"cpe:2.3:a:php:php"},
		},
		{
			ID:             "wordpress",
			Name:           "WordPress",
			Category:       "lang_framework",
			Vendor:         "WordPress",
			Description:    "WordPress 核心安全更新与高危漏洞通告",
			Homepage:       "https://wordpress.org/news/category/security/",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Packagist", Name: "wordpress/wordpress"},
			},
			GitHubRepos: []string{"WordPress/WordPress"},
			KEVKeywords: []string{"wordpress"},
			CPEHints:    []string{"cpe:2.3:a:wordpress:wordpress"},
		},

		// --- DevOps 与中间件 ---
		{
			ID:             "gitlab",
			Name:           "GitLab",
			Category:       "devops_middleware",
			Vendor:         "GitLab",
			Description:    "GitLab CE/EE 官方安全版本发布公告",
			Homepage:       "https://about.gitlab.com/releases/categories/releases/",
			DefaultWatched: false,
			VendorFeedID:   "gitlab_rss",
			KEVKeywords:    []string{"gitlab"},
			CPEHints:       []string{"cpe:2.3:a:gitlab:gitlab"},
		},
		{
			ID:             "jenkins",
			Name:           "Jenkins",
			Category:       "devops_middleware",
			Vendor:         "Jenkins",
			Description:    "CI/CD 平台 Jenkins 核心官方安全公告",
			Homepage:       "https://www.jenkins.io/security/advisories/",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Maven", Name: "org.jenkins-ci.main:jenkins-core"},
			},
			GitHubRepos: []string{"jenkinsci/jenkins"},
			KEVKeywords: []string{"jenkins"},
			CPEHints:    []string{"cpe:2.3:a:jenkins:jenkins"},
		},
		{
			ID:             "git",
			Name:           "Git",
			Category:       "devops_middleware",
			Vendor:         "Git Project",
			Description:    "分布式版本控制工具 Git 官方安全修复",
			Homepage:       "https://github.com/git/git/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Debian", Name: "git"},
				{Ecosystem: "Ubuntu", Name: "git"},
			},
			GitHubRepos: []string{"git/git"},
			KEVKeywords: []string{"git"},
			CPEHints:    []string{"cpe:2.3:a:git-scm:git"},
		},
		{
			ID:             "kafka",
			Name:           "Apache Kafka",
			Category:       "devops_middleware",
			Vendor:         "Apache",
			Description:    "分布式消息队列 Apache Kafka 安全更新",
			Homepage:       "https://kafka.apache.org/cve-list",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Maven", Name: "org.apache.kafka:kafka-clients"},
				{Ecosystem: "Maven", Name: "org.apache.kafka:kafka_2.13"},
			},
			GitHubRepos: []string{"apache/kafka"},
			KEVKeywords: []string{"apache kafka", "kafka"},
			CPEHints:    []string{"cpe:2.3:a:apache:kafka"},
		},
		{
			ID:             "grafana",
			Name:           "Grafana",
			Category:       "devops_middleware",
			Vendor:         "Grafana Labs",
			Description:    "可观测与监控仪表板平台 Grafana 官方安全公告",
			Homepage:       "https://grafana.com/security/security-advisories/",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Go", Name: "github.com/grafana/grafana"},
			},
			GitHubRepos: []string{"grafana/grafana"},
			KEVKeywords: []string{"grafana"},
			CPEHints:    []string{"cpe:2.3:a:grafana:grafana"},
		},
		{
			ID:             "minio",
			Name:           "MinIO",
			Category:       "devops_middleware",
			Vendor:         "MinIO",
			Description:    "高性能 S3 兼容对象存储 MinIO 安全公告",
			Homepage:       "https://github.com/minio/minio/security/advisories",
			DefaultWatched: false,
			OSVPackages: []OSVPackageRef{
				{Ecosystem: "Go", Name: "github.com/minio/minio"},
			},
			GitHubRepos: []string{"minio/minio"},
			KEVKeywords: []string{"minio"},
			CPEHints:    []string{"cpe:2.3:a:minio:minio"},
		},
	}

	for i := range items {
		items[i].CategoryLabel = CategoryLabel(items[i].Category)
	}
	return items
}

// BuiltinAppPresets returns convenient quick-select bundles for the self-service app picker.
func BuiltinAppPresets() []AppPreset {
	allIDs := make([]string, 0, 36)
	for _, a := range BuiltinAppCatalog() {
		allIDs = append(allIDs, a.ID)
	}
	return []AppPreset{
		{
			ID:          "minimal_core",
			Name:        "极简安全底座 (默认 4 款)",
			Description: "仅关注服务器最核心的 4 个底层安全组件：Linux Kernel、OpenSSH、OpenSSL、Nginx",
			AppIDs:      vault.DefaultWatchedVulnAppIDs(),
		},
		{
			ID:          "ops_infra",
			Name:        "通用运维基础设施",
			Description: "覆盖 OS、SSH/TLS、反代、容器与主流关系/缓存数据库",
			AppIDs: []string{
				"linux-kernel", "ubuntu", "debian", "openssh", "openssl", "sudo",
				"nginx", "docker", "mysql", "postgresql", "redis",
			},
		},
		{
			ID:          "cloud_native",
			Name:        "容器与云原生套件",
			Description: "覆盖容器运行时、Kubernetes、镜像仓库、云原生网关与可观测组件",
			AppIDs: []string{
				"linux-kernel", "openssh", "openssl", "nginx", "traefik",
				"docker", "containerd", "kubernetes", "harbor", "grafana", "minio",
			},
		},
		{
			ID:          "web_fullstack",
			Name:        "Web 与全栈开发框架",
			Description: "覆盖主流 Web 服务器、前后端语言运行时、Spring/React/Next.js 与常用数据库",
			AppIDs: []string{
				"nginx", "caddy", "golang", "nodejs", "python", "spring",
				"react", "nextjs", "php", "wordpress", "mysql", "postgresql", "redis",
			},
		},
		{
			ID:          "all_builtin",
			Name:        "全栈全量监控",
			Description: "启用全部内置 35 款全栈主流应用",
			AppIDs:      allIDs,
		},
	}
}

// BuildResolvedCatalog combines built-in apps and user-defined custom apps with their active watched status.
func BuildResolvedCatalog(settings vault.VulnSettings) []AppDefinition {
	watchedBuiltins := make(map[string]struct{}, len(settings.WatchedAppIDs))
	for _, id := range settings.WatchedAppIDs {
		watchedBuiltins[strings.ToLower(strings.TrimSpace(id))] = struct{}{}
	}
	builtin := BuiltinAppCatalog()
	out := make([]AppDefinition, 0, len(builtin)+len(settings.CustomApps))
	for _, item := range builtin {
		_, item.Watched = watchedBuiltins[item.ID]
		out = append(out, item)
	}
	for _, ca := range settings.CustomApps {
		def := CustomAppToDefinition(ca)
		out = append(out, def)
	}
	return out
}

// CustomAppToDefinition converts a user-configured VulnCustomApp into an AppDefinition for unified syncing.
func CustomAppToDefinition(ca vault.VulnCustomApp) AppDefinition {
	cat := ca.Category
	if cat == "" {
		cat = "custom"
	}
	def := AppDefinition{
		ID:            ca.ID,
		Name:          ca.Name,
		Category:      cat,
		CategoryLabel: CategoryLabel(cat),
		Vendor:        "自定义订阅",
		IsCustom:      true,
		Watched:       ca.Enabled,
	}
	switch ca.Kind {
	case "github_repo":
		def.Description = "自定义 GitHub 仓库官方安全公告: " + ca.Repo
		def.Homepage = "https://github.com/" + ca.Repo + "/security/advisories"
		def.GitHubRepos = []string{ca.Repo}
		def.KEVKeywords = []string{strings.ToLower(ca.Name)}
	case "osv_package":
		def.Description = "自定义 OSV 生态包漏洞追踪: " + ca.Ecosystem + " / " + ca.PackageName
		def.Homepage = "https://osv.dev/list?q=" + ca.PackageName
		def.OSVPackages = []OSVPackageRef{{Ecosystem: ca.Ecosystem, Name: ca.PackageName}}
		def.KEVKeywords = []string{strings.ToLower(ca.Name)}
	}
	return def
}

// LookupAppByID finds an AppDefinition in the resolved catalog.
func LookupAppByID(catalog []AppDefinition, id string) (AppDefinition, bool) {
	for _, item := range catalog {
		if item.ID == id {
			return item, true
		}
	}
	return AppDefinition{}, false
}

// IsValidBuiltinAppID reports whether an ID belongs to BuiltinAppCatalog.
func IsValidBuiltinAppID(id string) bool {
	target := strings.ToLower(strings.TrimSpace(id))
	return slices.ContainsFunc(BuiltinAppCatalog(), func(a AppDefinition) bool {
		return a.ID == target
	})
}
