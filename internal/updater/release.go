package updater

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const updaterUserAgent = "ServerNeedSafe-Updater/1.0"

// ReleaseAsset describes a downloadable file attached to a GitHub Release.
type ReleaseAsset struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"download_url"` // Canonical https://github.com/.../releases/download/... URL
}

// ReleaseInfo summarizes the discovered GitHub Release.
type ReleaseInfo struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	Body        string         `json:"body"`
	HTMLURL     string         `json:"html_url"`
	PublishedAt string         `json:"published_at,omitempty"`
	Prerelease  bool           `json:"prerelease"`
	Assets      []ReleaseAsset `json:"assets"`
	Source      string         `json:"source"` // "github_api" | "mirror_atom" | "mirror_redirect"
}

type githubAPIRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	Assets      []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

type atomFeed struct {
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	ID      string `xml:"id"`
	Title   string `xml:"title"`
	Updated string `xml:"updated"`
	Link    struct {
		Href string `xml:"href,attr"`
	} `xml:"link"`
	Content struct {
		Type string `xml:"type,attr"`
		Body string `xml:",chardata"`
	} `xml:"content"`
}

var (
	htmlBlockBreakRe = regexp.MustCompile(`(?i)</?(br|p|div|li|tr|h[1-6]|ul|ol)[^>]*>`)
	htmlTagStripRe   = regexp.MustCompile(`<[^>]+>`)
	multiBlankLineRe = regexp.MustCompile(`\n{3,}`)
)

// FetchLatestRelease discovers the latest matching GitHub Release.
// Strategy:
//  1. When official GitHub direct is permitted and fast/selected, query GitHub Releases API for full metadata.
//  2. Otherwise (or on API failure/rate-limit in China), query `releases.atom` via the fastest available China mirror.
//  3. Final fallback: follow `releases/latest` redirect header via mirror (stable channel only).
func FetchLatestRelease(
	ctx context.Context,
	client *http.Client,
	githubBaseURL string,
	apiBaseURL string,
	repoSlug string,
	includePrerelease bool,
	mirrorMode string,
	orderedMirrors []MirrorNode,
) (*ReleaseInfo, *MirrorNode, error) {
	if client == nil {
		client = newHTTPClient(10 * time.Second)
	}
	githubBaseURL = strings.TrimRight(githubBaseURL, "/")
	apiBaseURL = strings.TrimRight(apiBaseURL, "/")
	repoSlug = strings.Trim(repoSlug, "/")

	var errs []string

	// Decide whether to attempt GitHub API first:
	// - Always in "direct" mode.
	// - In "auto" mode when official direct is first in the probed list (fast overseas/direct network).
	tryDirectAPIFirst := mirrorMode == "direct" || (mirrorMode == "auto" && len(orderedMirrors) > 0 && orderedMirrors[0].Prefix == "")
	if tryDirectAPIFirst {
		apiTimeout := 8 * time.Second
		if mirrorMode == "auto" {
			apiTimeout = 5 * time.Second
		}
		apiCtx, cancel := context.WithTimeout(ctx, apiTimeout)
		rel, err := fetchFromGitHubAPI(apiCtx, client, apiBaseURL, githubBaseURL, repoSlug, includePrerelease)
		cancel()
		if err == nil && rel != nil {
			var direct *MirrorNode
			for i := range orderedMirrors {
				if orderedMirrors[i].Prefix == "" {
					cp := orderedMirrors[i]
					direct = &cp
					break
				}
			}
			return rel, direct, nil
		}
		if err != nil {
			errs = append(errs, "GitHub API: "+err.Error())
		}
		if mirrorMode == "direct" {
			return nil, nil, fmt.Errorf("无法从 GitHub 官方获取最新版本: %s", strings.Join(errs, "; "))
		}
	}

	// Query releases.atom across ordered candidate mirrors (fastest China mirror first).
	for i := range orderedMirrors {
		node := orderedMirrors[i]
		atomCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		rel, err := fetchFromReleasesAtom(atomCtx, client, githubBaseURL, repoSlug, includePrerelease, node)
		cancel()
		if err == nil && rel != nil {
			cp := node
			return rel, &cp, nil
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s(atom): %s", node.Name, summarizeNetErr(err)))
		}
	}

	// If we didn't try direct GitHub API earlier (e.g. China mirror was probed fastest but atom failed), try API now in auto mode.
	if !tryDirectAPIFirst && mirrorMode == "auto" {
		apiCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		rel, err := fetchFromGitHubAPI(apiCtx, client, apiBaseURL, githubBaseURL, repoSlug, includePrerelease)
		cancel()
		if err == nil && rel != nil {
			direct := MirrorNode{ID: "direct", Name: "GitHub 官方直连", Prefix: "", Region: "global", SupportsAPI: true}
			return rel, &direct, nil
		}
		if err != nil {
			errs = append(errs, "GitHub API: "+err.Error())
		}
	}

	// Final fallback for stable releases: probe /releases/latest redirect through mirrors.
	if !includePrerelease {
		for i := range orderedMirrors {
			node := orderedMirrors[i]
			redirCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
			rel, err := fetchFromLatestRedirect(redirCtx, client, githubBaseURL, repoSlug, node)
			cancel()
			if err == nil && rel != nil {
				cp := node
				return rel, &cp, nil
			}
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s(redirect): %s", node.Name, summarizeNetErr(err)))
			}
		}
	}

	if len(errs) == 0 {
		return nil, nil, errors.New("未配置任何可用的 GitHub 更新线路")
	}
	return nil, nil, fmt.Errorf("所有检测线路均不可用: %s", strings.Join(errs, " | "))
}

func fetchFromGitHubAPI(
	ctx context.Context,
	client *http.Client,
	apiBaseURL string,
	githubBaseURL string,
	repoSlug string,
	includePrerelease bool,
) (*ReleaseInfo, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/releases/latest", apiBaseURL, repoSlug)
	if includePrerelease {
		endpoint = fmt.Sprintf("%s/repos/%s/releases?per_page=10", apiBaseURL, repoSlug)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", updaterUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("仓库尚未发布任何 Release")
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("GitHub API 触发速率限制 (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}

	var chosen *githubAPIRelease
	if includePrerelease {
		var list []githubAPIRelease
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("解析 Release 列表失败: %w", err)
		}
		for i := range list {
			if !list[i].Draft && strings.TrimSpace(list[i].TagName) != "" {
				chosen = &list[i]
				break
			}
		}
		if chosen == nil {
			return nil, errors.New("未找到已发布的版本")
		}
	} else {
		var single githubAPIRelease
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, fmt.Errorf("解析最新 Release 失败: %w", err)
		}
		if strings.TrimSpace(single.TagName) == "" {
			return nil, errors.New("GitHub API 返回的 Release 缺少版本号")
		}
		chosen = &single
	}

	assets := make([]ReleaseAsset, 0, len(chosen.Assets))
	for _, a := range chosen.Assets {
		assets = append(assets, ReleaseAsset{
			Name:        a.Name,
			Size:        a.Size,
			DownloadURL: a.BrowserDownloadURL,
		})
	}
	if len(assets) == 0 {
		assets = defaultExpectedAssets(githubBaseURL, repoSlug, chosen.TagName)
	}

	title := strings.TrimSpace(chosen.Name)
	if title == "" {
		title = chosen.TagName
	}
	htmlURL := strings.TrimSpace(chosen.HTMLURL)
	if htmlURL == "" {
		htmlURL = fmt.Sprintf("%s/%s/releases/tag/%s", githubBaseURL, repoSlug, chosen.TagName)
	}

	return &ReleaseInfo{
		TagName:     strings.TrimSpace(chosen.TagName),
		Name:        title,
		Body:        strings.TrimSpace(chosen.Body),
		HTMLURL:     htmlURL,
		PublishedAt: strings.TrimSpace(chosen.PublishedAt),
		Prerelease:  chosen.Prerelease || IsPrereleaseTag(chosen.TagName),
		Assets:      assets,
		Source:      "github_api",
	}, nil
}

func fetchFromReleasesAtom(
	ctx context.Context,
	client *http.Client,
	githubBaseURL string,
	repoSlug string,
	includePrerelease bool,
	node MirrorNode,
) (*ReleaseInfo, error) {
	atomURL := fmt.Sprintf("%s/%s/releases.atom", githubBaseURL, repoSlug)
	fetchURL := BuildMirroredURL(node, atomURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", updaterUserAgent)
	req.Header.Set("Accept", "application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	var feed atomFeed
	if err := xml.Unmarshal(raw, &feed); err != nil {
		return nil, fmt.Errorf("解析 Atom XML 失败: %w", err)
	}

	for _, entry := range feed.Entries {
		tag := extractTagFromAtomEntry(entry)
		if tag == "" {
			continue
		}
		isPre := IsPrereleaseTag(tag)
		if isPre && !includePrerelease {
			continue
		}
		title := strings.TrimSpace(entry.Title)
		if title == "" {
			title = tag
		}
		notes := cleanAtomHTMLNotes(entry.Content.Body)
		return &ReleaseInfo{
			TagName:     tag,
			Name:        title,
			Body:        notes,
			HTMLURL:     fmt.Sprintf("%s/%s/releases/tag/%s", githubBaseURL, repoSlug, tag),
			PublishedAt: strings.TrimSpace(entry.Updated),
			Prerelease:  isPre,
			Assets:      defaultExpectedAssets(githubBaseURL, repoSlug, tag),
			Source:      "mirror_atom",
		}, nil
	}
	return nil, errors.New("releases.atom 中未找到符合通道条件的版本")
}

func fetchFromLatestRedirect(
	ctx context.Context,
	client *http.Client,
	githubBaseURL string,
	repoSlug string,
	node MirrorNode,
) (*ReleaseInfo, error) {
	latestURL := fmt.Sprintf("%s/%s/releases/latest", githubBaseURL, repoSlug)
	fetchURL := BuildMirroredURL(node, latestURL)

	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", updaterUserAgent)

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	loc := strings.TrimSpace(resp.Header.Get("Location"))
	tag := extractTagFromReleaseURL(loc)
	if tag == "" {
		return nil, fmt.Errorf("未从重定向头识别出版本标签 (HTTP %d)", resp.StatusCode)
	}

	return &ReleaseInfo{
		TagName:    tag,
		Name:       "ServerNeedSafe " + tag,
		Body:       "",
		HTMLURL:    fmt.Sprintf("%s/%s/releases/tag/%s", githubBaseURL, repoSlug, tag),
		Prerelease: IsPrereleaseTag(tag),
		Assets:     defaultExpectedAssets(githubBaseURL, repoSlug, tag),
		Source:     "mirror_redirect",
	}, nil
}

func extractTagFromAtomEntry(entry atomEntry) string {
	if tag := extractTagFromReleaseURL(entry.Link.Href); tag != "" {
		return tag
	}
	// Atom <id> often looks like "tag:github.com,2008:Repository/12345/v2.3.0"
	if idx := strings.LastIndexByte(entry.ID, '/'); idx >= 0 && idx+1 < len(entry.ID) {
		cand := strings.TrimSpace(entry.ID[idx+1:])
		if _, err := ParseSemVer(cand); err == nil {
			return cand
		}
	}
	return ""
}

func extractTagFromReleaseURL(rawURL string) string {
	const marker = "/releases/tag/"
	idx := strings.Index(rawURL, marker)
	if idx < 0 {
		return ""
	}
	rest := rawURL[idx+len(marker):]
	if q := strings.IndexAny(rest, "?#/"); q >= 0 {
		rest = rest[:q]
	}
	return strings.TrimSpace(rest)
}

func cleanAtomHTMLNotes(rawHTML string) string {
	if strings.TrimSpace(rawHTML) == "" {
		return ""
	}
	s := htmlBlockBreakRe.ReplaceAllString(rawHTML, "\n")
	s = htmlTagStripRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	lines := strings.Split(s, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		cleaned = append(cleaned, strings.TrimSpace(line))
	}
	joined := strings.Join(cleaned, "\n")
	joined = multiBlankLineRe.ReplaceAllString(joined, "\n\n")
	return strings.TrimSpace(joined)
}

func defaultExpectedAssets(githubBaseURL, repoSlug, tag string) []ReleaseAsset {
	base := fmt.Sprintf("%s/%s/releases/download/%s/", strings.TrimRight(githubBaseURL, "/"), strings.Trim(repoSlug, "/"), tag)
	names := []string{
		"ServerNeedSafe-windows-amd64.exe",
		"ServerNeedSafe-windows-arm64.exe",
		"sns-server-linux-amd64",
		"sns-server-linux-arm64",
		"SHA256SUMS.txt",
	}
	out := make([]ReleaseAsset, 0, len(names))
	for _, name := range names {
		out = append(out, ReleaseAsset{
			Name:        name,
			DownloadURL: base + name,
		})
	}
	return out
}

func findAssetDownloadURL(rel *ReleaseInfo, githubBaseURL, repoSlug, assetName string) string {
	if rel != nil {
		for _, a := range rel.Assets {
			if a.Name == assetName && strings.TrimSpace(a.DownloadURL) != "" {
				return a.DownloadURL
			}
		}
		if rel.TagName != "" {
			return fmt.Sprintf("%s/%s/releases/download/%s/%s",
				strings.TrimRight(githubBaseURL, "/"),
				strings.Trim(repoSlug, "/"),
				rel.TagName,
				assetName,
			)
		}
	}
	return ""
}
